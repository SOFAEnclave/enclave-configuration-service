#include <map>
#include <string>

#include "./sgx_trts.h"

#include "unified_attestation/ua_trusted.h"

#include "aecs/error.h"
#include "aecs/version.h"

#include "trusted/trusted_cert.h"
#include "trusted/trusted_functions.h"
#include "trusted/trusted_storage.h"

#include "./aecs.pb.h"
#include "./enclave_t.h"

using google::protobuf::util::JsonStringToMessage;

using kubetee::attestation::TeeInstance;
using kubetee::trusted::StorageTrustedBridge;

using kubetee::AdminRemoteCallRequest;
using kubetee::AdminRemoteCallResponse;
using kubetee::AecsAdminInitializeRequest;
using kubetee::AecsAdminInitializeResponse;

using kubetee::DigitalEnvelopeEncrypted;
using kubetee::EnclaveSecret;
using kubetee::EnclaveSecretPolicy;
using kubetee::UnifiedAttestationAttributes;
using kubetee::UnifiedAttestationAuthReport;

typedef TeeErrorCode (*AecsAdminRemoteFunction)(const std::string& req_str,
                                                std::string* res_str,
                                                std::string* out_str);
typedef TeeErrorCode (*ServiceAdminRemoteFunction)(
    const std::string& service_name,
    const std::string& req_str,
    std::string* res_str);

// The storage layout:
//  aecsIdentity/
//  ├── host1
//  ├── host2
//  ├── ...
//  └── hostN
//  aecs
//  ├── service1
//  │   ├── authentication
//  │   ├── secrets
//  │   │   ├── secret1
//  │   │   ├── secret2
//  │   │   ├── ...
//  │   │   └── secretN
//  ├── service2
//  │   ├── authentication
//  │   ├── secrets
//  │   │   ├── secret1
//  │   │   ├── secret2
//  │   │   ├── ...
//  │   │   └── secretN
//
// When unregister the service, just remove aecs/servicename/*
// and when list services, just list aecs/* (folders only)
static const char kStorageFolderPrefix[] = "aecs/";
// Full service authentication: aecs/serviceName/authentication
static const char kStorageServiceAuthSuffix[] = "/authentication";
// Full secret name: aecs/serivceName/secrets/secretName
static const char kStorageSecertSuffix[] = "/secrets/";

// Full identity key name: aecs_identity_key_<node-sn>
static const char kStoragePrefixIdentity[] = "aecsIdentity/";

// AECS status constant
static const char kAecsStatusNewPending[] = "Pending";
static const char kAecsStatusWorking[] = "Working";

// All secert created by trusted applications use this service name
static const char kTaServiceName[] = "TrustedApplications";

static constexpr size_t kMaxServicesNum = 256;
static constexpr size_t kMaxSecretsNum = 32;
static constexpr size_t kMaxSecretLength = 10240;

static constexpr unsigned int kCertDefaultBitLength = 2048;
static constexpr unsigned int kCertDefaultDays = 3650;

static kubetee::AdminAuth gAecsAdminAuth;
static std::string gAecsStatus = kAecsStatusNewPending;
static std::string gIdentityBackup;

#ifdef __cplusplus
extern "C" {
#endif

static TeeErrorCode VerifyAdminPassword(const std::string& function_name,
                                        const std::string& auth_password,
                                        const std::string& req_password) {
  // Ignore the password check if the admin password is not set
  if (auth_password.empty()) {
    ELOG_DEBUG("No password authentication");
    return TEE_SUCCESS;
  }

  // Exclude some special cases by function name, ignore password check
  if (function_name == "AecsListBackupIdentity") {
    ELOG_DEBUG("Ignore password authentication");
    return TEE_SUCCESS;
  }

  kubetee::common::DataBytes req_password_bytes(req_password);
  // Do password authentication after it is set.
  ELOG_DEBUG("AECS admin request with password authentication");
  if (req_password_bytes.ToSHA256().ToHexStr().GetStr() != auth_password) {
    ELOG_ERROR("Invalid password authentication");
    return AECS_ERROR_ADMIN_AUTH_INVALID_PASSWORD;
  }

  return TEE_SUCCESS;
}

static TeeErrorCode VerifyAecsEnclave(
    const UnifiedAttestationAuthReport& auth) {
  // Verify the remote enclave MRSIGNER and PRODID
  // Don't require the same MRENCLAVE/ISVSVN in case connection
  // from different version of AECS enclave instances
  // Don't require the same user data because aecs has nonce value
  // in report, see also EnclaveInstance::CreateRaReport()
  kubetee::UnifiedAttestationPolicy policy;
  kubetee::UnifiedAttestationAttributes* attr = policy.add_main_attributes();
  attr->CopyFrom(TeeInstance::GetInstance().GetEnclaveInfo());
  attr->clear_hex_ta_measurement();
  attr->clear_str_min_isvsvn();
  attr->clear_hex_user_data();
  // from different tee platform
  attr->clear_str_tee_platform();
  TEE_CHECK_RETURN(UaVerifyAuthReport(auth, policy));
  return TEE_SUCCESS;
}

TeeErrorCode VerifySecretPolicy(const UnifiedAttestationAuthReport& auth,
                                const EnclaveSecretPolicy& policy) {
  const kubetee::UnifiedAttestationPolicy& secret_policy = policy.policy();
  TEE_LOG_DEBUG("Secret policy attributes entries size: %ld",
                secret_policy.main_attributes_size());
  TEE_CHECK_RETURN(UaVerifyAuthReport(auth, secret_policy));
  return TEE_SUCCESS;
}

static TeeErrorCode EnvelopeEncryptAndSign(const std::string& encrypt_pubkey,
                                           const std::string& plain,
                                           const std::string& nonce,
                                           DigitalEnvelopeEncrypted* env) {
  // Always sign plain by identity private key
  std::string prvkey = TeeInstance::GetInstance().GetIdentity().private_key();
  std::string name = nonce.empty() ? kDefaultEnvelopeName : nonce;
  kubetee::common::DigitalEnvelope envelope(name);
  TEE_CHECK_RETURN(envelope.Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(envelope.Sign(prvkey, plain, env));
  return TEE_SUCCESS;
}

static TeeErrorCode EnvelopeDecryptAndVerify(
    const std::string& verify_pubkey,
    const DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  // Always decrypt cipher by identity private key
  std::string prvkey = TeeInstance::GetInstance().GetIdentity().private_key();

  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

static TeeErrorCode DecryptAndVerifyRemoteRequest(
    const kubetee::AdminRemoteCallRequest& admin_req,
    const kubetee::AdminAuth& auth,
    std::string* func_req_str) {
  // Decrypt the encrypted request (AdminRemoteCallReqWithAuth)
  kubetee::AdminRemoteCallReqWithAuth remote_call_req;
  if (admin_req.has_req_enc()) {
    std::string remote_call_req_str;
    TEE_CHECK_RETURN(EnvelopeDecryptAndVerify(
        auth.public_key(), admin_req.req_enc(), &remote_call_req_str));
    JSON2PB(remote_call_req_str, &remote_call_req);
  }

  // Do password authentication after it is set.
  const std::string& func_name = admin_req.function_name();
  TEE_CHECK_RETURN(VerifyAdminPassword(admin_req.function_name(),
                                       auth.password_hash(),
                                       remote_call_req.password()));

  func_req_str->assign(remote_call_req.req());
  return TEE_SUCCESS;
}

static TeeErrorCode InitializeAecsAdmin(const kubetee::AdminAuth& admin) {
  if (admin.public_key().empty()) {
    ELOG_ERROR("Empty AECS administrator public key");
    return AECS_ERROR_ADMIN_AUTH_EMPTY_PUBLIC_KEY;
  }

  ELOG_INFO("InitializeAecsAdmin");
  gAecsAdminAuth = admin;
  return TEE_SUCCESS;
}

static TeeErrorCode CheckNameValidity(const std::string& name) {
  // Should not be empty
  if (name.empty()) {
    ELOG_ERROR("Empty name");
    return AECS_ERROR_PARAMETER_NAME_EMPTY;
  }
  // Use the most normal Linux name style, reserve some special characters
  if (name.size() >= 256) {
    ELOG_ERROR("Name is too long");
    return AECS_ERROR_PARAMETER_NAME_TOO_LONG;
  }
  // Only allow [a-zA-Z0-9_-.] in names
  for (int i = 0; i < name.size(); i++) {
    if (('a' <= name[i] && name[i] <= 'z') ||
        ('A' <= name[i] && name[i] <= 'Z') ||
        ('0' <= name[i] && name[i] <= '9') || (name[i] == '_') ||
        (name[i] == '-') || (name[i] == '.')) {
      continue;
    }
    ELOG_ERROR("Invalid name with special characters: '%s'", name.c_str());
    return AECS_ERROR_PARAMETER_NAME_INVALID_CHAR;
  }
  // Execlude special reserved names
  if (name == kTaServiceName) {
    ELOG_ERROR("In conflict with reserved names: '%s'", name.c_str());
    return AECS_ERROR_PARAMETER_NAME_RESERVED;
  }
  return TEE_SUCCESS;
}

static std::string GetServiceAuthName(const std::string& service_name) {
  return kStorageFolderPrefix + service_name + kStorageServiceAuthSuffix;
}

static std::string GetSecretPrefix(const std::string& service_name) {
  return kStorageFolderPrefix + service_name + kStorageSecertSuffix;
}

static std::string ParseParamStr(const kubetee::EnclaveSecretSpec& spec,
                                 const std::string& name) {
  // As the parameters list is very short, so just search all each time
  for (size_t i = 0; i < spec.params_size(); i++) {
    const kubetee::EnclaveKvPair& param = spec.params(i);
    if (param.key() == name) {
      return param.value();
    }
  }
  return "";  // return empty string if not find
}

static int ParseParamInt(const kubetee::EnclaveSecretSpec& spec,
                         const std::string& name,
                         int default_value) {
  std::string v = ParseParamStr(spec, name);
  return v.empty() ? default_value : std::stoi(v);
}

static TeeErrorCode SecretPrepareDataRsaKeyPair(
    const kubetee::EnclaveSecretSpec& spec, std::string* data) {
  bool is_pkcs8 = (ParseParamStr(spec, "pkcs_type") == "pkcs8") ? true : false;
  int bits = ParseParamInt(spec, "bit_length", 0);
  kubetee::AsymmetricKeyPair keypair;
  if (data->empty()) {
    // Create the RSA key pair secret
    kubetee::common::RsaCrypto rsa(bits, is_pkcs8);
    TEE_CHECK_RETURN(rsa.GenerateKeyPair(keypair.mutable_public_key(),
                                         keypair.mutable_private_key()));
    PB2JSON(keypair, data);
  } else {
    // Base64 decode data can write it back
    kubetee::common::DataBytes data_b64(*data);
    data->assign(data_b64.FromBase64().GetStr());
    // Check the initialized data JSON format
    // Don't check the pem file itself here
    JSON2PB(*data, &keypair);
    ELOG_INFO("Using initialized data");
  }
  return TEE_SUCCESS;
}

static TeeErrorCode SecretPrepareDataSm2KeyPair(std::string* data) {
  kubetee::AsymmetricKeyPair keypair;
  if (data->empty()) {
    // Generate the SM key pair secret
    kubetee::common::SM2Crypto sm2_crypto;
    TEE_CHECK_RETURN(sm2_crypto.GenerateKeyPair(keypair.mutable_public_key(),
                                                keypair.mutable_private_key()));
    PB2JSON(keypair, data);
  } else {
    // Check the initialized data JSON format
    // Don't check the pem file itself here
    kubetee::common::DataBytes data_b64(*data);
    data->assign(data_b64.FromBase64().GetStr());
    JSON2PB(*data, &keypair);
    ELOG_INFO("Using initialized data");
  }
  return TEE_SUCCESS;
}

static TeeErrorCode SecretPrepareDataAes256Key(std::string* data) {
  size_t aes_key_size = kubetee::common::AesGcmCrypto::get_key_size();
  if (data->empty()) {
    // Create the AES256 key secret
    kubetee::common::DataBytes aes_key(aes_key_size);
    sgx_status_t sgx_ret = sgx_read_rand(aes_key.data(), aes_key.size());
    if (sgx_ret == SGX_SUCCESS) {
      data->assign(aes_key.ToHexStr().GetStr());
    } else {
      ELOG_ERROR("Fail to read SGX rand as AES key");
      return AECS_ERROR_CODE(sgx_ret);
    }
  } else if (data->length() != (2 * aes_key_size)) {
    ELOG_ERROR("%ld bytes hex string is expected", 2 * aes_key_size);
    return AECS_ERROR_SECRET_CREATE_INITIALIZED_DATA;
  } else {
    ELOG_INFO("Using initialized data");
  }
  return TEE_SUCCESS;
}

static TeeErrorCode SecretPrepareDataImport(std::string* data) {
  // Check the imported data length
  if (data->empty()) {
    ELOG_ERROR("There is no secret data to be imported");
    return AECS_ERROR_SECRET_CREATE_EMPTY_DATE;
  }
  if (data->size() > kMaxSecretLength) {
    ELOG_ERROR("The secret size is too large");
    return AECS_ERROR_SECRET_CREATE_DATA_TOO_LONG;
  }
  return TEE_SUCCESS;
}

static TeeErrorCode SecretPrepareDataCertificate(
    const kubetee::EnclaveSecretSpec& spec, std::string* data) {
  kubetee::SslCredentialsOptions credentials;
  if (data->empty()) {
    // Create the X509 certificate secret
    int bits = ParseParamInt(spec, "bit_length", kCertDefaultBitLength);
    int days = ParseParamInt(spec, "days", kCertDefaultDays);
    ELOG_DEBUG("Certificate bit_length/days=%d/%d", bits, days);
    kubetee::trusted::X509Certificate cert(bits, days);
    TEE_CHECK_RETURN(cert.CreateSslCredentials(&credentials));
    PB2JSON(credentials, data);
  } else {
    // Check the initialized data JSON format
    // Don't check the pem file itself here
    kubetee::common::DataBytes data_b64(*data);
    data->assign(data_b64.FromBase64().GetStr());
    JSON2PB(*data, &credentials);
    ELOG_INFO("Using initialized data");
  }
  return TEE_SUCCESS;
}

static TeeErrorCode SecretPrepareDataConfigurations(
    const kubetee::EnclaveSecretSpec& spec, std::string* data) {
  // Create the configuration list secret
  kubetee::EnclaveConfigurations confs;
  for (size_t i = 0; i < spec.params_size(); i++) {
    confs.add_items()->CopyFrom(spec.params(i));
  }
  PB2JSON(confs, data);
  ELOG_DEBUG("Configurations: %s", data->c_str());
  return TEE_SUCCESS;
}

static TeeErrorCode SecretPrepareData(kubetee::EnclaveSecret* secret) {
  const kubetee::EnclaveSecretSpec& spec = secret->spec();
  const kubetee::EnclaveSecretType type = spec.type();
  const char* secret_name = spec.secret_name().c_str();
  std::string* data = secret->mutable_data();
  ELOG_INFO("Create secret: %s, type=%d", secret_name, SCAST(int, type));
  if (type == kubetee::SECRET_TYPE_RSA_KEY_PAIR) {
    TEE_CHECK_RETURN(SecretPrepareDataRsaKeyPair(spec, data));
  } else if (type == kubetee::SECRET_TYPE_SM2_KEY_PAIR) {
    TEE_CHECK_RETURN(SecretPrepareDataSm2KeyPair(data));
  } else if (type == kubetee::SECRET_TYPE_AES256_KEY) {
    TEE_CHECK_RETURN(SecretPrepareDataAes256Key(data));
  } else if (type == kubetee::SECRET_TYPE_IMPORT_DATA) {
    TEE_CHECK_RETURN(SecretPrepareDataImport(data));
  } else if (type == kubetee::SECRET_TYPE_CERTIFICATE) {
    TEE_CHECK_RETURN(SecretPrepareDataCertificate(spec, data));
  } else if (type == kubetee::SECRET_TYPE_CONFIGURATIONS) {
    TEE_CHECK_RETURN(SecretPrepareDataConfigurations(spec, data));
  } else {
    ELOG_ERROR("Unsupported secret type");
    return AECS_ERROR_SECRET_CREATE_UNSUPPORTED_TYPE;
  }
  return TEE_SUCCESS;
}

static TeeErrorCode checkAecsStatusWorking() {
  if (gAecsStatus != kAecsStatusWorking) {
    ELOG_ERROR("AecsServer is not running in Working Status");
    return AECS_ERROR_SERVER_NOT_WORKING_STATUS;
  }

  return TEE_SUCCESS;
}

static TeeErrorCode GetEnclaveStatus(kubetee::EnclaveStatus* status) {
  status->set_version(AECS_CURRENT_VERSION);
  // Get Enclave status
  status->set_status(gAecsStatus);

  if (checkAecsStatusWorking() == TEE_SUCCESS) {
    // Get the idenity backup name
    bool identity_exist = false;
    std::string identity_name = kStoragePrefixIdentity + gIdentityBackup;
    ELOG_DEBUG("Check identity backup on stograge %s", identity_name.c_str());
    StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
    TeeErrorCode ret = storage.CheckExist(identity_name, &identity_exist);
    if ((ret != TEE_SUCCESS) || !identity_exist) {
      status->set_identity_backup(gIdentityBackup + "Invalid");
    } else {
      status->set_identity_backup(gIdentityBackup);
    }
  } else {
    ELOG_WARN("AecsServer is not running in Working Status");
    status->set_identity_backup("Unknown");
  }

  // Get the enclave identity public hash
  TeeInstance& ti = TeeInstance::GetInstance();
  const kubetee::AsymmetricKeyPair& identity = ti.GetIdentity();
  kubetee::common::DataBytes pubhash(identity.public_key());
  status->set_identity_hash(pubhash.ToSHA256().ToHexStr().GetStr());

  // Get the enclave information
  status->mutable_attr()->CopyFrom(ti.GetEnclaveInfo());

  return TEE_SUCCESS;
}

TeeErrorCode TeeGetEnclaveStatus(const std::string& req_str,
                                 std::string* res_str) {
  kubetee::GetAecsStatusRequest req;
  kubetee::GetAecsStatusResponse res;
  JSON2PB(req_str, &req);

  kubetee::EnclaveStatus enclave_status;
  TEE_CHECK_RETURN(GetEnclaveStatus(&enclave_status));

  // Prepare the return repsonse with status and signature
  PB2JSON(enclave_status, res.mutable_status_str());
  kubetee::common::DigitalEnvelope envelope;
  std::string prvkey = TeeInstance::GetInstance().GetIdentity().private_key();
  kubetee::DigitalEnvelopeEncrypted* env = res.mutable_status_sig();
  TEE_CHECK_RETURN(envelope.Sign(prvkey, res.status_str(), env));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeGetRemoteSecret(const std::string& req_str,
                                std::string* res_str) {
  if (gAecsStatus != kAecsStatusWorking) {
    ELOG_ERROR("It is not working state for remote sync");
    return AECS_ERROR_SERVER_NOT_WORKING_FOR_SYNC;
  }

  kubetee::GetRemoteSecretRequest req;
  kubetee::DigitalEnvelopeEncrypted res;
  JSON2PB(req_str, &req);

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(req.auth_ra_report()));

  // Prepare the secret string
  kubetee::AecsServerSecrets secrets;
  secrets.mutable_identity()->CopyFrom(
      TeeInstance::GetInstance().GetIdentity());
  secrets.mutable_storage_auth()->CopyFrom(
      StorageTrustedBridge::GetInstance().GetAuth());
  secrets.mutable_admin()->CopyFrom(gAecsAdminAuth);
  std::string secrets_str;
  PB_SERIALIZE(secrets, &secrets_str);

  // Encrypt and sign the identity keys
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Encrypt(req.auth_ra_report().pem_public_key(),
                                    secrets_str, &res));
  TEE_CHECK_RETURN(
      envelope.Sign(secrets.identity().private_key(), secrets_str, &res));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeUnpackRemoteSecret(const std::string& req_str,
                                   std::string* res_str) {
  kubetee::GetRemoteSecretResponse req;
  kubetee::UnifiedFunctionGenericResponse res;
  JSON2PB(req_str, &req);

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(req.auth_ra_report()));

  // Decrypt and verify the digital envelope encrypted identity keys
  TeeInstance& ti = TeeInstance::GetInstance();
  std::string secrets_str;
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(ti.GetIdentity().private_key(),
                                    req.secret_keys_enc(), &secrets_str));
  TEE_CHECK_RETURN(envelope.Verify(req.auth_ra_report().pem_public_key(),
                                   secrets_str, req.secret_keys_enc()));
  kubetee::AecsServerSecrets secrets;
  PB_PARSE(secrets, secrets_str);

  // Save the storage authentication information, allow to update exisit one
  // This means we allow to do sync repeatly.
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.SetAuth(secrets.storage_auth(), true));

  // Save the AECS admin public key
  TEE_CHECK_RETURN(InitializeAecsAdmin(secrets.admin()));

  // Seal the new identity which will be saved in untrusted part
  std::string identity_str;
  PB_SERIALIZE(secrets.identity(), &identity_str);
  std::string sealed_identity;
  TEE_CHECK_RETURN(ti.SealData(identity_str, &sealed_identity, false));
  kubetee::common::DataBytes hex_sealed_identity(sealed_identity);
  res.add_result(hex_sealed_identity.ToHexStr().GetStr());

  // Update the AECS status after sync the aecs secret and apply it here
  ELOG_INFO("Swith to working status after remote sync");
  gAecsStatus = kAecsStatusWorking;

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminRegisterEnclaveService(const std::string& req_str,
                                             std::string* res_str,
                                             std::string* out_str) {
  kubetee::RegisterEnclaveServiceRequest req;
  kubetee::RegisterEnclaveServiceResponse res;
  JSON2PB(req_str, &req);

  // Check whether there are special characters in service name
  TEE_CHECK_RETURN(CheckNameValidity(req.service_name()));

  // Check whether achieve to the max number of services
  std::string list_prefix = kStorageFolderPrefix;
  kubetee::StorageListAllResponse list_res;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.ListAll(list_prefix, &list_res));
  ELOG_INFO("Current service number: %ld", list_res.names_size());
  if (list_res.names_size() >= kMaxServicesNum) {
    ELOG_ERROR("Achieve to the max number of services");
    return AECS_ERROR_SERVICE_MAX_REGISTERED;
  }

  // Create the service admin authentication object
  kubetee::AdminAuth service_auth;
  service_auth.set_public_key(req.service_pubkey());
  service_auth.set_password_hash(req.service_password_hash());
  std::string service_auth_str;
  PB_SERIALIZE(service_auth, &service_auth_str);

  // Write the service admin authentication object
  std::string name = GetServiceAuthName(req.service_name());
  TEE_CHECK_RETURN(storage.Create(name, service_auth_str));

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminUnregisterEnclaveService(const std::string& req_str,
                                               std::string* res_str,
                                               std::string* out_str) {
  kubetee::UnregisterEnclaveServiceRequest req;
  kubetee::UnregisterEnclaveServiceResponse res;
  JSON2PB(req_str, &req);

  if (req.service_name().empty()) {
    ELOG_ERROR("Empty service name to be unregistered");
    return AECS_ERROR_ADMIN_EMPTYY_SERVICE_NAME;
  }

  // Add "/" to avoid remove 'abc' for 'ab' case
  std::string name = kStorageFolderPrefix + req.service_name() + "/";
  TEE_CHECK_RETURN(StorageTrustedBridge::GetInstance().Delete(name));

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminListEnclaveService(const std::string& req_str,
                                         std::string* res_str,
                                         std::string* out_str) {
  kubetee::ListEnclaveServiceRequest req;
  kubetee::ListEnclaveServiceResponse res;
  JSON2PB(req_str, &req);

  // If service_name is not specified, list all service names
  std::string list_prefix = kStorageFolderPrefix;
  if (!req.service_name().empty()) {
    list_prefix.append(req.service_name());
  }
  // List all the names of service
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.ListAll(list_prefix, res.mutable_services()));

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

static TeeErrorCode AecsProvisionReloadIdentity(const std::string& host_name,
                                                std::string* out_identity) {
  // Check if need to reload or save the identity backup
  if (host_name.empty()) {
    ELOG_WARN("No node name for identity key backup");
    return TEE_SUCCESS;
  }
  // Check whether there are special characters in host name
  TEE_CHECK_RETURN(CheckNameValidity(host_name));

  // Seal the current identity key
  TeeInstance& ti = TeeInstance::GetInstance();
  const kubetee::AsymmetricKeyPair& identity = ti.GetIdentity();
  std::string identity_str;
  PB_SERIALIZE(identity, &identity_str);
  std::string sealed_identity;
  TEE_CHECK_RETURN(ti.SealData(identity_str, &sealed_identity, false));
  kubetee::common::DataBytes hex_sealed_identity(sealed_identity);
  hex_sealed_identity.ToHexStr().Void();

  // Check whether the identity key backup exist
  bool identity_exist = false;
  std::string identity_name = kStoragePrefixIdentity;
  identity_name.append(host_name);
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.CheckExist(identity_name, &identity_exist));
  if (identity_exist) {
    // Reload the identity key backup from storage
    std::string backup_str;
    kubetee::AecsIdentityBackup identity_backup;
    TEE_CHECK_RETURN(storage.GetValue(identity_name, &backup_str, false));
    PB_PARSE(identity_backup, backup_str);
    if (identity_backup.hex_sealed_identity() == hex_sealed_identity.GetStr()) {
      ELOG_INFO("No need to reload the same identity key");
    } else {
      ELOG_INFO("Reload the identity key backup on %s", host_name.c_str());
      out_identity->assign(identity_backup.hex_sealed_identity());
    }
  } else {
    // Save the identity key backup to storage
    ELOG_INFO("Save the identity key backup on %s", host_name.c_str());
    kubetee::AecsIdentityBackup identity_backup;
    kubetee::common::DataBytes pkey_hash(identity.public_key());
    identity_backup.set_hex_sealed_identity(hex_sealed_identity.GetStr());
    identity_backup.set_public_key_hash(
        pkey_hash.ToSHA256().ToHexStr().GetStr());
    ELOG_DEBUG("Hash: %s", identity_backup.public_key_hash().c_str());
    std::string identity_backup_str;
    PB_SERIALIZE(identity_backup, &identity_backup_str);
    // Don't care about the wrong things, for example, there is already
    // the older identity key backup for the same node, will not overwrite it.
    TEE_CHECK_RETURN(storage.Create(identity_name, identity_backup_str, false));
  }

  gIdentityBackup = host_name;
  return TEE_SUCCESS;
}

TeeErrorCode AecsProvision(const std::string& req_str,
                           std::string* res_str,
                           std::string* out_str) {
  kubetee::AecsProvisionRequest req;
  kubetee::AecsProvisionResponse res;
  JSON2PB(req_str, &req);

  // Return success only for the first time to set the storage authentication
  TEE_CHECK_RETURN(StorageTrustedBridge::GetInstance().SetAuth(req.auth()));

  // Get the sealed identity key backup if it existed
  TEE_CHECK_RETURN(AecsProvisionReloadIdentity(req.host_name(), out_str));

  // Update the AECS status
  ELOG_INFO("Swith to working status after provision");
  gAecsStatus = kAecsStatusWorking;

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode AecsBackupIdentity(const std::string& req_str,
                                std::string* res_str,
                                std::string* out_str) {
  kubetee::AecsBackupIdentityRequest req;
  kubetee::AecsBackupIdentityResponse res;
  JSON2PB(req_str, &req);

  // Check if need to reload or save the identity backup
  if (req.host_name().empty()) {
    ELOG_WARN("Empty node name for identity key backup");
    return TEE_SUCCESS;
  }
  // Check whether there are special characters in host name
  TEE_CHECK_RETURN(CheckNameValidity(req.host_name()));

  // Seal the current identity key
  TeeInstance& ti = TeeInstance::GetInstance();
  const kubetee::AsymmetricKeyPair& identity = ti.GetIdentity();
  std::string identity_str;
  PB_SERIALIZE(identity, &identity_str);
  std::string sealed_identity;
  TEE_CHECK_RETURN(ti.SealData(identity_str, &sealed_identity, false));
  kubetee::common::DataBytes hex_sealed_identity(sealed_identity);
  hex_sealed_identity.ToHexStr().Void();

  // Prepare the identity backup data
  kubetee::AecsIdentityBackup identity_backup;
  kubetee::common::DataBytes pkey_hash(identity.public_key());
  identity_backup.set_hex_sealed_identity(hex_sealed_identity.GetStr());
  identity_backup.set_public_key_hash(pkey_hash.ToSHA256().ToHexStr().GetStr());
  ELOG_DEBUG("Hash: %s", identity_backup.public_key_hash().c_str());
  std::string identity_backup_str;
  PB_SERIALIZE(identity_backup, &identity_backup_str);

  // Create or update the backup in storage
  std::string identity_name = kStoragePrefixIdentity;
  identity_name.append(req.host_name());
  ELOG_INFO("Backup the identity key on %s", req.host_name().c_str());
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.Update(identity_name, identity_backup_str, false));
  gIdentityBackup = req.host_name();

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

TeeErrorCode AecsListBackupIdentity(const std::string& req_str,
                                    std::string* res_str,
                                    std::string* out_str) {
  kubetee::AecsListBackupIdentityRequest req;
  kubetee::AecsListBackupIdentityResponse res;
  JSON2PB(req_str, &req);

  // If service_name is not specified, list all service names
  std::string list_prefix = kStoragePrefixIdentity;
  if (!req.host_name().empty()) {
    list_prefix.append(req.host_name());
  }

  // List all the names of service
  kubetee::StorageListAllResponse storage_res;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.ListAll(list_prefix, &storage_res));
  for (int i = 0; i < storage_res.names_size(); i++) {
    const std::string& name = storage_res.names()[i];
    kubetee::AecsListIdentityBackupResult* result = res.add_results();
    result->set_identity_backup_name(name);

    // set the public key hash if parse it successfully, otherwise,
    // return error string to this bakcup object name.
    std::string value;
    storage.GetValue(kStoragePrefixIdentity + name, &value, false);
    kubetee::AecsIdentityBackup identity_backup;
    if (identity_backup.ParseFromString(value)) {
      result->set_identity_public_key_hash(identity_backup.public_key_hash());
    } else {
      ELOG_WARN("Fail to parse identity backup: %s", name.c_str());
      result->set_identity_public_key_hash("Invalid Data or wrong version");
    }
    ELOG_DEBUG("Name: %s", result->identity_backup_name().c_str());
    ELOG_DEBUG("Hash: %s", result->identity_public_key_hash().c_str());
  }

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

TeeErrorCode AecsDeleteBackupIdentity(const std::string& req_str,
                                      std::string* res_str,
                                      std::string* out_str) {
  kubetee::AecsDeleteBackupIdentityRequest req;
  kubetee::AecsDeleteBackupIdentityResponse res;
  JSON2PB(req_str, &req);

  if (req.host_name().empty()) {
    ELOG_ERROR("Empty backup host name to be deleted");
    return AECS_ERROR_ADMIN_EMPTYY_HOST_NAME;
  }

  // Delete the backup with specified name
  bool exist = false;
  std::string name = kStoragePrefixIdentity + req.host_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.Delete(name, false));

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminListTaSecrets(const std::string& req_str,
                                    std::string* res_str,
                                    std::string* out_str) {
  kubetee::AecsListTaSecretRequest req;
  kubetee::AecsListTaSecretResponse res;
  JSON2PB(req_str, &req);

  // If service_name is not specified, list all secrets
  std::string secrets_dir = GetSecretPrefix(kTaServiceName);
  std::string list_prefix = secrets_dir;
  if (!req.secret_name().empty()) {
    // The secret_name maybe a pattern including begining characters
    list_prefix.append(req.secret_name());
  }

  // Get the names firstly and get secret with data one by one
  // Only return the policies list, but not the real secret data
  kubetee::StorageListAllResponse storage_res;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  ELOG_INFO("AecsAdminListTaSecrets: %s", list_prefix.c_str());
  TEE_CHECK_RETURN(storage.ListAll(list_prefix, &storage_res));
  // ListAll will return filename only whther the prefix is dir or filename
  for (int i = 0; i < storage_res.names_size(); i++) {
    std::string value;
    storage.GetValue(secrets_dir + storage_res.names()[i], &value);
    kubetee::EnclaveSecret secret;
    PB_PARSE(secret, value);
    res.add_secrets()->CopyFrom(secret.spec());
  }

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminDestroyTaSecrets(const std::string& req_str,
                                       std::string* res_str,
                                       std::string* out_str) {
  kubetee::AecsDestroyTaSecretRequest req;
  kubetee::AecsDestroyTaSecretResponse res;
  JSON2PB(req_str, &req);

  if (req.secret_name().empty()) {
    ELOG_ERROR("There is no secret name");
    return AECS_ERROR_SECRET_DESTROY_EMPTY_NAME;
  }

  // Delete the secret object by secret name
  std::string full_name = GetSecretPrefix(kTaServiceName) + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  ELOG_INFO("ServiceDestroySecret: %s", full_name.c_str());
  TEE_CHECK_RETURN(storage.Delete(full_name));

  PB2JSON(res, res_str);
  out_str->clear();
  return TEE_SUCCESS;
}

TeeErrorCode TeeAecsAdminRemoteCall(const std::string& req_str,
                                    std::string* res_str) {
  static std::map<std::string, AecsAdminRemoteFunction> functions = {
      {"RegisterEnclaveService", AecsAdminRegisterEnclaveService},
      {"UnregisterEnclaveService", AecsAdminUnregisterEnclaveService},
      {"ListEnclaveService", AecsAdminListEnclaveService},
      {"AecsProvision", AecsProvision},
      {"AecsBackupIdentity", AecsBackupIdentity},
      {"AecsListBackupIdentity", AecsListBackupIdentity},
      {"AecsDeleteBackupIdentity", AecsDeleteBackupIdentity},
      {"ListTaSecret", AecsAdminListTaSecrets},
      {"DestroyTaSecret", AecsAdminDestroyTaSecrets}};
  kubetee::AdminRemoteCallRequest req;
  kubetee::AdminRemoteCallResponse res;
  JSON2PB(req_str, &req);

  // Decrypt and verify the encrypted request
  std::string freq_str;
  TEE_CHECK_RETURN(
      DecryptAndVerifyRemoteRequest(req, gAecsAdminAuth, &freq_str));

  // Call the real trusted function
  std::string name = req.function_name();
  if (functions.find(name) == functions.end()) {
    ELOG_ERROR("Cannot find function: %s", name.c_str());
    return AECS_ERROR_ADMIN_FUNCTION_NAME;
  }

  // check aecs_server running status
  if (name != "AecsProvision") {
    TEE_CHECK_RETURN(checkAecsStatusWorking());
  }

  std::string fres_str;
  std::string* out_str = res.mutable_res_plain();
  AecsAdminRemoteFunction function = functions[name];
  TEE_CHECK_RETURN((*function)(freq_str, &fres_str, out_str));
  ELOG_INFO("AecsAdminRemoteCall %s successfully", name.c_str());

  // If the response is empty, then the res_enc will also be empty
  if (!fres_str.empty()) {
    // Encrypt by AECS admin public key and sign by identity private key
    DigitalEnvelopeEncrypted* res_enc = res.mutable_res_enc();
    std::string empty_nonce;
    TEE_CHECK_RETURN(EnvelopeEncryptAndSign(gAecsAdminAuth.public_key(),
                                            fres_str, empty_nonce, res_enc));
  } else {
    ELOG_DEBUG("No response from %s", name.c_str());
  }

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminCreateSecret(const std::string& service_name,
                                      const std::string& req_str,
                                      std::string* res_str) {
  kubetee::CreateEnclaveSecretRequest req;
  kubetee::CreateEnclaveSecretResponse res;
  JSON2PB(req_str, &req);

  // Check the parameters in request
  const kubetee::EnclaveSecretSpec& new_spec = req.secret().spec();
  if (new_spec.service_name().empty()) {
    ELOG_ERROR("There is no service name");
    return AECS_ERROR_SECRET_CREATE_EMPTY_SERVICE_NAME;
  }
  if (new_spec.service_name() != service_name) {
    ELOG_ERROR("Service names mismatch in req and option");
    return AECS_ERROR_SECRET_CREATE_MISMATCH_SERVICE_NAME;
  }

  // Check whether there are special characters in secret name
  std::string secret_name = new_spec.secret_name();
  TEE_CHECK_RETURN(CheckNameValidity(secret_name));

  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  std::string full_name = GetSecretPrefix(service_name) + secret_name;
  // If update the secret, will report error when secret doesn't exist
  // If create new secret, will report error when secret exist
  if (req.is_update()) {
    // Get the enclave secret keys by service and secret name
    std::string secret_str;
    std::string name = GetSecretPrefix(service_name) + secret_name;
    TEE_CHECK_RETURN(storage.GetValue(name, &secret_str));
    kubetee::EnclaveSecret secret;
    PB_PARSE(secret, secret_str);
    if (service_name != secret.spec().service_name()) {
      ELOG_ERROR("Service name does not match when update secret");
      return AECS_ERROR_SECRET_UPDATE_MISMATCH_SERVICE_NAME;
    }
    if (secret_name != secret.spec().secret_name()) {
      ELOG_ERROR("Secret name does not match when update secret");
      return AECS_ERROR_SECRET_UPDATE_MISMATCH_SECRET_NAME;
    }
    if (new_spec.type() != secret.spec().type()) {
      ELOG_ERROR("Secret type does not match when update secret");
      return AECS_ERROR_SECRET_UPDATE_NO_SECRET_TYPE;
    }
    if (secret.spec().readonly() != "false") {
      ELOG_ERROR("Do not allow to update readonly secret");
      return AECS_ERROR_SECRET_UPDATE_READONLY_SECRET;
    }

    // Just update the policy, keep the other things unmodified
    secret.mutable_spec()
        ->mutable_policy()
        ->mutable_policy()
        ->clear_main_attributes();
    secret.mutable_spec()->mutable_policy()->CopyFrom(new_spec.policy());

    // Write the secret to storage
    std::string new_secret_str;
    PB_SERIALIZE(secret, &new_secret_str);
    ELOG_INFO("ServiceAdminUpdateSecret: %s", full_name.c_str());
    TEE_CHECK_RETURN(storage.Update(full_name, new_secret_str));
  } else {
    // Check whether achieve to the max number of secrets
    std::string list_prefix = GetSecretPrefix(service_name);
    kubetee::StorageListAllResponse list_res;
    TEE_CHECK_RETURN(storage.ListAll(list_prefix, &list_res));
    ELOG_INFO("Current number of secrets: %ld", list_res.names_size());
    if (list_res.names_size() >= kMaxSecretsNum) {
      ELOG_ERROR("Achieve to the max number of secrets");
      return AECS_ERROR_SECRET_CREATE_ACHIEVE_MAX;
    }

    // Generate secret data according to the secret type
    TEE_CHECK_RETURN(SecretPrepareData(req.mutable_secret()));

    // Write the secret to storage
    std::string new_secret_str;
    PB_SERIALIZE(req.secret(), &new_secret_str);
    ELOG_INFO("ServiceAdminCreateSecret: %s", full_name.c_str());
    TEE_CHECK_RETURN(storage.Create(full_name, new_secret_str));
  }

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminDestroySecret(const std::string& service_name,
                                       const std::string& req_str,
                                       std::string* res_str) {
  kubetee::DestroyEnclaveSecretRequest req;
  kubetee::DestroyEnclaveSecretResponse res;
  JSON2PB(req_str, &req);

  if (req.secret_name().empty()) {
    ELOG_ERROR("There is no secret name");
    return AECS_ERROR_SECRET_DESTROY_EMPTY_NAME;
  }

  // Delete the secret object by secret name
  std::string full_name = GetSecretPrefix(service_name) + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  ELOG_INFO("ServiceDestroySecret: %s", full_name.c_str());
  TEE_CHECK_RETURN(storage.Delete(full_name));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminListSecret(const std::string& service_name,
                                    const std::string& req_str,
                                    std::string* res_str) {
  kubetee::ListEnclaveSecretRequest req;
  kubetee::ListEnclaveSecretResponse res;
  JSON2PB(req_str, &req);

  // If service_name is not specified, list all secrets
  std::string secrets_dir = GetSecretPrefix(service_name);
  std::string list_prefix = secrets_dir;
  if (!req.secret_name().empty()) {
    // The secret_name maybe a pattern including begining characters
    list_prefix.append(req.secret_name());
  }

  // Get the names firstly and get secret with data one by one
  // Only return the policies list, but not the real secret data
  kubetee::StorageListAllResponse storage_res;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  ELOG_INFO("ServiceAdminListSecret: %s", list_prefix.c_str());
  TEE_CHECK_RETURN(storage.ListAll(list_prefix, &storage_res));
  // ListAll will return filename only whther the prefix is dir or filename
  for (int i = 0; i < storage_res.names_size(); i++) {
    std::string value;
    storage.GetValue(secrets_dir + storage_res.names()[i], &value);
    kubetee::EnclaveSecret secret;
    PB_PARSE(secret, value);
    res.add_secrets()->CopyFrom(secret.spec());
  }

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeServiceAdminRemoteCall(const std::string& req_str,
                                       std::string* res_str) {
  static std::map<std::string, ServiceAdminRemoteFunction> functions = {
      {"CreateSecret", ServiceAdminCreateSecret},
      {"DestroySecret", ServiceAdminDestroySecret},
      {"ListSecret", ServiceAdminListSecret}};

  kubetee::AdminRemoteCallRequest req;
  kubetee::AdminRemoteCallResponse res;
  JSON2PB(req_str, &req);

  std::string function_name = req.function_name();
  std::string service_name = req.req_enc().aes_cipher().aad();
  ELOG_INFO("ServiceAdminRemoteCall: function:%s", function_name.c_str());
  ELOG_INFO("ServiceAdminRemoteCall: service:%s", service_name.c_str());

  // check aecs_server running status
  TEE_CHECK_RETURN(checkAecsStatusWorking());

  // Get the service administrator authentication settings from storage
  std::string service_auth_str;
  std::string service_auth_name = GetServiceAuthName(service_name);
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.GetValue(service_auth_name, &service_auth_str));
  kubetee::AdminAuth service_auth;
  PB_PARSE(service_auth, service_auth_str);

  // Decrypt and verify the encrypted request
  std::string freq_str;
  TEE_CHECK_RETURN(DecryptAndVerifyRemoteRequest(req, service_auth, &freq_str));
  PB_SERIALIZE(service_auth, &service_auth_str);
  TEE_CHECK_RETURN(storage.Update(service_auth_name, service_auth_str));

  // Call the real trusted function
  if (functions.find(function_name) == functions.end()) {
    ELOG_ERROR("Cannot find function: %s", function_name.c_str());
    return AECS_ERROR_SERVICE_FUNCTION_NAME;
  }
  std::string fres_str;
  ServiceAdminRemoteFunction function = functions[function_name];
  TEE_CHECK_RETURN((*function)(service_name, freq_str, &fres_str));
  ELOG_INFO("ServiceAdminRemoteCall %s successfully", function_name.c_str());

  // If the response is empty, then the res_enc will also be empty
  if (!fres_str.empty()) {
    // Encrypt by AECS admin public key and sign by identity private key
    DigitalEnvelopeEncrypted* res_enc = res.mutable_res_enc();
    std::string empty_nonce;
    TEE_CHECK_RETURN(EnvelopeEncryptAndSign(service_auth.public_key(), fres_str,
                                            empty_nonce, res_enc));
  } else {
    ELOG_DEBUG("No response from %s", function_name.c_str());
  }

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeGetEnclaveSecret(const std::string& req_str,
                                 std::string* res_str) {
  // check aecs_server running status
  TEE_CHECK_RETURN(checkAecsStatusWorking());

  kubetee::GetEnclaveSecretRequest req;
  kubetee::GetEnclaveSecretResponse res;
  JSON2PB(req_str, &req);

  // Get the enclave secret keys by service and secret name
  std::string secret_str;
  std::string name = GetSecretPrefix(req.service_name()) + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.GetValue(name, &secret_str));
  ELOG_INFO("Get enclave secret: %s/%s", req.service_name().c_str(),
            req.secret_name().c_str());

  // Check the service and secret name in secret
  kubetee::EnclaveSecret secret;
  PB_PARSE(secret, secret_str);
  if (req.service_name() != secret.spec().service_name()) {
    ELOG_ERROR("Service name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GET_MISMATCH_SERVICE_NAME;
  }
  if (req.secret_name() != secret.spec().secret_name()) {
    ELOG_ERROR("Secret name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GET_MISMATCH_SECRET_NAME;
  }

  // Verify the enclave service RA report by the secret policy
  const kubetee::UnifiedAttestationAuthReport& auth = req.auth_ra_report();
  TEE_CHECK_RETURN(VerifySecretPolicy(auth, secret.spec().policy()));

  // Encrypt the secret by the enclave service public key
  TEE_CHECK_RETURN(EnvelopeEncryptAndSign(auth.pem_public_key(), secret.data(),
                                          req.nonce(),
                                          res.mutable_secret_enc()));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeGetEnclaveSecretPublic(const std::string& req_str,
                                       std::string* res_str) {
  // check aecs_server running status
  TEE_CHECK_RETURN(checkAecsStatusWorking());

  kubetee::GetEnclaveSecretPublicRequest req;
  kubetee::GetEnclaveSecretPublicResponse res;
  JSON2PB(req_str, &req);

  ELOG_INFO("Get enclave secret public: %s/%s", req.service_name().c_str(),
            req.secret_name().c_str());

  // [FIXME] To client service_token authentication here if it is necessary

  // Get the enclave secret keys by service and secret name
  std::string secret_str;
  std::string name = GetSecretPrefix(req.service_name()) + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.GetValue(name, &secret_str));

  // Check the service and secret name in secret
  kubetee::EnclaveSecret secret;
  PB_PARSE(secret, secret_str);
  if (req.service_name() != secret.spec().service_name()) {
    ELOG_ERROR("Service name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GETPUB_MISMATCH_SERVICE_NAME;
  }
  if (req.secret_name() != secret.spec().secret_name()) {
    ELOG_ERROR("Secret name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GETPUB_MISMATCH_SECRET_NAME;
  }

  // Get public key from secret
  kubetee::common::RsaCrypto rsa;
  const kubetee::EnclaveSecretType type = secret.spec().type();
  std::string* secret_data_pub = secret.mutable_data();
  if (type == kubetee::SECRET_TYPE_RSA_KEY_PAIR ||
      type == kubetee::SECRET_TYPE_SM2_KEY_PAIR) {
    // Get public key from the RSA key pair secret
    kubetee::AsymmetricKeyPair keypair;
    JSON2PB(secret.data(), &keypair);
    secret_data_pub->assign(keypair.public_key());
  } else if (type == kubetee::SECRET_TYPE_CERTIFICATE) {
    // Get certificate from the Certificate secret
    kubetee::SslCredentialsOptions x509;
    JSON2PB(secret.data(), &x509);
    secret_data_pub->assign(x509.cert_chain());
  } else {
    // Always return spec if allow to share
    // Just no public key
    secret_data_pub->clear();
  }

  // Clear the sensitive message
  const kubetee::UnifiedAttestationPolicy& secret_policy =
      secret.spec().policy().policy();
  for (int i = 0; i < secret_policy.main_attributes_size(); i++) {
    // It's not so necessary to clear spid as it also in RA report
    // secret_policy.mutable_main_attributes(i)->clear_hex_spid();
  }

  // Clear all if it is not allowed to be shared
  std::string share = secret.spec().share();
  if (share != "public") {
    secret.Clear();
    secret.mutable_spec()->set_share(share);
  }

  // Sign the secret by AECS identity private key
  std::string res_secret_json;
  PB2JSON(secret, &res_secret_json);
  res.set_secret_public(res_secret_json);
  res.set_nonce(req.nonce());

  res_secret_json += req.nonce();
  std::string res_secret_sig;
  std::string prvkey = TeeInstance::GetInstance().GetIdentity().private_key();
  kubetee::common::AsymmetricCrypto asymmetric_crypto;
  TEE_CHECK_RETURN(
      asymmetric_crypto.Sign(prvkey, res_secret_json, &res_secret_sig));
  kubetee::common::DataBytes signature_b64(res_secret_sig);

  res.set_signature_b64(signature_b64.ToBase64().GetStr());

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeCreateTaSecret(const std::string& req_str,
                               std::string* res_str) {
  // check aecs_server running status
  TEE_CHECK_RETURN(checkAecsStatusWorking());

  kubetee::CreateTaSecretRequest req;
  kubetee::CreateTaSecretResponse res;
  JSON2PB(req_str, &req);

  // Validate the secret name
  kubetee::EnclaveSecretSpec* secret_spec =
      req.mutable_secret()->mutable_spec();
  const std::string& secret_name = secret_spec->secret_name();
  TEE_CHECK_RETURN(CheckNameValidity(secret_name));

  // Complete and adjust the spec to be saved
  // Trusted application bound sceret all use a default service name
  const std::string service_name = kTaServiceName;
  secret_spec->set_service_name(service_name);
  secret_spec->set_readonly("true");
  secret_spec->set_share("false");

  // Verify the trusted application RA report by the secret policy
  kubetee::UnifiedAttestationPolicy* secret_policy =
      secret_spec->mutable_policy()->mutable_policy();
  const kubetee::UnifiedAttestationAuthReport& auth = req.auth_ra_report();
  UnifiedAttestationAttributes* attr = secret_policy->add_main_attributes();
  attr->Clear();
  TEE_CHECK_RETURN(UaGetAuthReportAttr(auth, attr));
  // Don't check public key and user data
  secret_policy->clear_pem_public_key();
  attr->clear_hex_hash_or_pem_pubkey();

  // Check whether achieve to the max number of secrets
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  std::string list_prefix = GetSecretPrefix(service_name);
  kubetee::StorageListAllResponse list_res;
  TEE_CHECK_RETURN(storage.ListAll(list_prefix, &list_res));
  ELOG_INFO("Current number of secrets: %ld", list_res.names_size());
  if (list_res.names_size() >= kMaxSecretsNum) {
    ELOG_ERROR("Achieve to the max number of secrets");
    return AECS_ERROR_SECRET_CREATE_ACHIEVE_MAX;
  }

  // Generate secret data according to the secret type
  TEE_CHECK_RETURN(SecretPrepareData(req.mutable_secret()));

  // Write the secret to storage
  std::string secret_str;
  PB_SERIALIZE(req.secret(), &secret_str);
  std::string full_name = GetSecretPrefix(service_name) + secret_name;
  ELOG_INFO("TaCreateSecret: %s", full_name.c_str());
  TEE_CHECK_RETURN(storage.Create(full_name, secret_str));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeDestroyTaSecret(const std::string& req_str,
                                std::string* res_str) {
  // check aecs_server running status
  TEE_CHECK_RETURN(checkAecsStatusWorking());

  kubetee::DestroyTaSecretRequest req;
  kubetee::DestroyTaSecretResponse res;
  JSON2PB(req_str, &req);

  // Check the parameters in request
  if (req.secret_name().empty()) {
    ELOG_ERROR("There is no secret name");
    return AECS_ERROR_SECRET_DESTROY_EMPTY_NAME;
  }

  // Read the secret and check the policy in spec
  const std::string& service_name = kTaServiceName;
  std::string secret_str;
  std::string full_name = GetSecretPrefix(service_name) + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.GetValue(full_name, &secret_str));
  ELOG_INFO("Get enclave secret: %s/%s", service_name.c_str(),
            req.secret_name().c_str());

  // Check the service and secret name in secret
  kubetee::EnclaveSecret secret;
  PB_PARSE(secret, secret_str);
  if (service_name != secret.spec().service_name()) {
    ELOG_ERROR("Service name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GET_MISMATCH_SERVICE_NAME;
  }
  if (req.secret_name() != secret.spec().secret_name()) {
    ELOG_ERROR("Secret name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GET_MISMATCH_SECRET_NAME;
  }

  // Verify the trusted application RA report by the secret policy
  // Only allow the trusted application which created this secret to delete it
  const kubetee::UnifiedAttestationAuthReport& auth = req.auth_ra_report();
  TEE_CHECK_RETURN(VerifySecretPolicy(auth, secret.spec().policy()));

  // Delete all the secret objects by secret name
  ELOG_INFO("TaDestroySecret: %s", full_name.c_str());
  TEE_CHECK_RETURN(storage.Delete(full_name));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeGetTaSecret(const std::string& req_str, std::string* res_str) {
  // check aecs_server running status
  TEE_CHECK_RETURN(checkAecsStatusWorking());

  kubetee::GetTaSecretRequest req;
  kubetee::GetTaSecretResponse res;
  JSON2PB(req_str, &req);

  // Get the enclave secret keys by service and secret name
  std::string secret_str;
  std::string service_name = kTaServiceName;
  std::string name = GetSecretPrefix(service_name) + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.GetValue(name, &secret_str));
  ELOG_INFO("Get ta secret: %s/%s", req.secret_name().c_str());

  // Check the service and secret name in secret
  kubetee::EnclaveSecret secret;
  PB_PARSE(secret, secret_str);
  if (service_name != secret.spec().service_name()) {
    ELOG_ERROR("Service name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GET_MISMATCH_SERVICE_NAME;
  }
  if (req.secret_name() != secret.spec().secret_name()) {
    ELOG_ERROR("Secret name does not match what in the secret spec");
    return AECS_ERROR_SECRET_GET_MISMATCH_SECRET_NAME;
  }

  // Verify the enclave service RA report by the secret policy
  const kubetee::UnifiedAttestationAuthReport& auth = req.auth_ra_report();
  TEE_CHECK_RETURN(VerifySecretPolicy(auth, secret.spec().policy()));

  // Encrypt the secret by the enclave service public key
  TEE_CHECK_RETURN(EnvelopeEncryptAndSign(auth.pem_public_key(), secret.data(),
                                          req.nonce(),
                                          res.mutable_secret_enc()));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeInitializeAecsAdmin(const std::string& req_str,
                                    std::string* res_str) {
  kubetee::AecsAdminInitializeRequest req;
  kubetee::AecsAdminInitializeResponse res;
  JSON2PB(req_str, &req);

  if (!gAecsAdminAuth.public_key().empty()) {
    ELOG_ERROR("AECS administrator public key already exists");
    return AECS_ERROR_ADMIN_INIT_EXISTED_PUBLIC_KEY;
  }

  TEE_CHECK_RETURN(InitializeAecsAdmin(req.admin()));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeInitializeAecsEnclave(const std::string& req_str,
                                      std::string* res_str) {
  kubetee::AecsInitializeEnclaveRequest req;
  kubetee::AecsInitializeEnclaveResponse res;
  JSON2PB(req_str, &req);

  TeeInstance& ti = TeeInstance::GetInstance();
  std::string identity_str;
  if (!req.hex_sealed_identity().empty()) {
    kubetee::common::DataBytes sealed_identity(req.hex_sealed_identity());
    TEE_CHECK_RETURN(sealed_identity.FromHexStr().GetError());
    TEE_CHECK_RETURN(ti.UnsealData(sealed_identity.GetStr(), &identity_str));
    kubetee::AsymmetricKeyPair identity;
    PB_PARSE(identity, identity_str);
    TEE_CHECK_RETURN(ti.ImportIdentity(identity));
    res.set_enclave_hex_sealed_identity(req.hex_sealed_identity());
    ELOG_INFO("Replace identity key pair successfully");
  } else {
    TEE_CHECK_RETURN(ti.CreateIdentity());
    std::string sealed_identity;
    PB_SERIALIZE(ti.GetIdentity(), &identity_str);
    TEE_CHECK_RETURN(ti.SealData(identity_str, &sealed_identity, false));
    kubetee::common::DataBytes hex_sealed_identity(sealed_identity);
    TEE_CHECK_RETURN(hex_sealed_identity.ToHexStr().GetError());
    res.set_enclave_hex_sealed_identity(hex_sealed_identity.GetStr());
    ELOG_INFO("Generate new identity key pair successfully");
  }
  kubetee::common::DataBytes pubhash(ti.GetIdentity().public_key());
  ELOG_INFO("Identity HASH: %s", pubhash.GetSHA256HexStr().c_str());

  // Return identity public key by response
  res.set_enclave_public_key(ti.GetIdentity().public_key());

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode RegisterTrustedUnifiedFunctionsEx() {
  ELOG_DEBUG("Register application trusted functions");
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeGetEnclaveStatus);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeGetRemoteSecret);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeUnpackRemoteSecret);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeAecsAdminRemoteCall);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeServiceAdminRemoteCall);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeGetEnclaveSecret);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeGetEnclaveSecretPublic);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeCreateTaSecret);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeDestroyTaSecret);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeGetTaSecret);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeInitializeAecsAdmin);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeInitializeAecsEnclave);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
