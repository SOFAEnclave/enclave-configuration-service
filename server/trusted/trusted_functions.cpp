#include <map>
#include <string>

#include "./sgx_trts.h"

#include "tee/common/aes.h"
#include "tee/common/challenger.h"
#include "tee/common/envelope.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/rsa.h"
#include "tee/common/type.h"
#include "tee/trusted/trusted_pbcall.h"
#include "tee/trusted/utils/trusted_seal.h"

#include "trusted/trusted_functions.h"
#include "trusted/trusted_storage.h"

#include "./aecs.pb.h"
#include "./enclave_t.h"

using tee::trusted::StorageTrustedBridge;
using tee::trusted::TeeInstance;

using tee::AdminRemoteCallRequest;
using tee::AdminRemoteCallResponse;
using tee::AecsAdminInitializeRequest;
using tee::AecsAdminInitializeResponse;
using tee::EnclaveSecret;
using tee::EnclaveSecretPolicy;
using tee::ListEnclaveSecretRequest;
using tee::ListEnclaveSecretResponse;
using tee::RaReportAuthentication;
using tee::RegisterEnclaveServiceRequest;
using tee::RegisterEnclaveServiceResponse;

typedef TeeErrorCode (*AecsAdminRemoteFunction)(const std::string& req_str,
                                                std::string* res_str);
typedef TeeErrorCode (*ServiceAdminRemoteFunction)(
    const std::string& service_name,
    const std::string& req_str,
    std::string* res_str);

// we use suffix here, and service name as prefix
// when delete all service objects, just remove <service_name>_xxxx
//
static const char kServiceSeparator[] = "#";
// Full public key name: <service_name>_admin_public_key
static const char kStorageSuffixServiceAuth[] = "#service#authentication";
// Full secret name: <service_name>_secret_<secret_name>
static const char kStorageSuffixServiceSecret[] = "#secret#";

// Full identity key name: aecs_identity_key_<node-sn>
static const char kStoragePrefixIdentity[] = "identity@";

static constexpr size_t kMaxSecretLength = 10240;

static tee::AdminAuth kAecsAdminAuth;

#ifdef __cplusplus
extern "C" {
#endif

static TeeErrorCode VerifyAecsEnclave(const RaReportAuthentication& auth) {
  // Verify the remote enclave MRSIGNER and PRODID
  // Don't require the same MRENCLAVE/ISVSVN in case connection
  // from different version of AECS enclave instances
  tee::EnclaveMatchRules rules;
  tee::EnclaveInformation* rule = rules.add_entries();
  rule->CopyFrom(TeeInstance::GetInstance().GetEnclaveInfo());
  rule->clear_hex_mrenclave();
  rule->clear_hex_min_isvsvn();
  tee::common::RaChallenger verifier(auth.public_key(), rules);
  TEE_CHECK_RETURN(verifier.VerifyReport(auth.ias_report()));
  return TEE_SUCCESS;
}

TeeErrorCode VerifySecretPolicy(const RaReportAuthentication& auth,
                                const EnclaveSecretPolicy& policy) {
  const tee::EnclaveMatchRules& rules = policy.rules();
  TEE_LOG_DEBUG("RA report match rules size: %ld", rules.entries_size());
  tee::common::RaChallenger ch(auth.public_key(), rules);
  TEE_CHECK_RETURN(ch.VerifyReport(auth.ias_report()));
  return TEE_SUCCESS;
}

static TeeErrorCode VerifyAecsAdmin(const DigitalEnvelopeEncrypted& env) {
  tee::common::RsaCrypto rsa;
  TEE_CHECK_RETURN(rsa.Verify(
      kAecsAdminAuth.public_key(), env.plain_hash(), env.plain_hash_sig()));
  return TEE_SUCCESS;
}

static TeeErrorCode VerifyAdminSignature(const std::string& public_key,
                                         const DigitalEnvelopeEncrypted& env) {
  // Calculate the HASH value of service and verify the signature
  tee::common::DataBytes service_name(env.aes_cipher().aad());
  tee::common::RsaCrypto rsa;
  TEE_CHECK_RETURN(rsa.Verify(
      public_key, service_name.ToSHA256().GetStr(), env.plain_hash_sig()));
  return TEE_SUCCESS;
}

static TeeErrorCode EnvelopeEncryptAndSign(const std::string& encrypt_pubkey,
                                           const std::string& plain,
                                           tee::DigitalEnvelopeEncrypted* env) {
  // Always sign plain by identity private key
  tee::KeyPair& identity = TeeInstance::GetInstance().GetIdentity();

  tee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(envelope.Sign(identity.private_key(), plain, env));
  return TEE_SUCCESS;
}

static TeeErrorCode EnvelopeDecryptAndVerify(
    const std::string& verify_pubkey,
    const tee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  // Always decrypt cipher by identity private key
  std::string prvkey = TeeInstance::GetInstance().GetIdentity().private_key();

  tee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

static TeeErrorCode DecryptAndVerifyRemoteRequest(
    const tee::DigitalEnvelopeEncrypted& env,
    tee::AdminAuth* auth,
    std::string* req) {
  // Decrypt the encrypted request (AdminRemoteCallReqWithAuth)
  std::string remote_call_req_str;
  TEE_CHECK_RETURN(
      EnvelopeDecryptAndVerify(auth->public_key(), env, &remote_call_req_str));
  tee::AdminRemoteCallReqWithAuth remote_call_req;
  PB_PARSE(remote_call_req, remote_call_req_str);

  // Do password authentication after it is set.
  if (!auth->password_hash().empty()) {
    ELOG_DEBUG("AECS admin request with password authentication");
    if (remote_call_req.password_hash() != auth->password_hash()) {
      ELOG_ERROR("Invalid password authentication");
      return TEE_ERROR_PARAMETERS;
    }
  } else {
    ELOG_DEBUG("No password authentication");
  }

  // Check sequence number
  ELOG_DEBUG("AECS admin request sequence: %ld/%ld",
             remote_call_req.sequence(),
             auth->sequence());
  if (remote_call_req.sequence() <= auth->sequence()) {
    ELOG_ERROR("Invalid sequence number in AECS admin request");
    return TEE_ERROR_PARAMETERS;
  } else {
    // Add AECS admin request sequence number in server side
    int curr_seq = auth->sequence();
    int64_t next_seq = curr_seq ? (curr_seq + 1) : remote_call_req.sequence();
    auth->set_sequence(next_seq);
  }

  req->assign(remote_call_req.req());
  return TEE_SUCCESS;
}

static TeeErrorCode InitializeAecsAdmin(const tee::AdminAuth& admin) {
  if (admin.public_key().empty()) {
    ELOG_ERROR("Empty AECS administrator public key");
    return TEE_ERROR_PARAMETERS;
  }

  kAecsAdminAuth = admin;
  return TEE_SUCCESS;
}

static TeeErrorCode CheckNamevalidity(const std::string& name) {
  // Use the most normal Linux name style, reserve some special characters
  if (name.size() >= 256) {
    ELOG_ERROR("Name is too long");
    return TEE_ERROR_PARAMETERS;
  }
  // Only allow [a-zA-Z0-9_-.] in names
  for (int i = 0; i < name.size(); i++) {
    if (('a' <= name[i] && name[i] <= 'z') ||
        ('A' <= name[i] && name[i] <= 'Z') ||
        ('0' <= name[i] && name[i] <= '9') || (name[i] == '_') ||
        (name[i] == '-') || (name[i] == '.')) {
      continue;
    }
    ELOG_ERROR("Invalid name with special characters");
    return TEE_ERROR_PARAMETERS;
  }
  return TEE_SUCCESS;
}

TeeErrorCode TeeGetRemoteSecret(const std::string& req_str,
                                std::string* res_str) {
  tee::GetRemoteSecretRequest req;
  tee::DigitalEnvelopeEncrypted res;
  PB_PARSE(req, req_str);

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(req.auth_ra_report()));

  // Prepare the secret string
  tee::AecsServerSecrets secrets;
  secrets.mutable_identity()->CopyFrom(
      TeeInstance::GetInstance().GetIdentity());
  secrets.mutable_storage_auth()->CopyFrom(
      StorageTrustedBridge::GetInstance().GetAuth());
  secrets.mutable_admin()->CopyFrom(kAecsAdminAuth);
  std::string secrets_str;
  PB_SERIALIZE(secrets, &secrets_str);

  // Encrypt and sign the identity keys
  tee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(
      envelope.Encrypt(req.auth_ra_report().public_key(), secrets_str, &res));
  TEE_CHECK_RETURN(
      envelope.Sign(secrets.identity().private_key(), secrets_str, &res));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeUnpackRemoteSecret(const std::string& req_str,
                                   std::string* res_str) {
  tee::GetRemoteSecretResponse req;
  tee::PbGenericResponse res;
  PB_PARSE(req, req_str);

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(req.auth_ra_report()));

  // Decrypt and verify the digital envelope encrypted identity keys
  TeeInstance& ti = TeeInstance::GetInstance();
  std::string secrets_str;
  tee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(
      ti.GetIdentity().private_key(), req.secret_keys_enc(), &secrets_str));
  TEE_CHECK_RETURN(envelope.Verify(
      req.auth_ra_report().public_key(), secrets_str, req.secret_keys_enc()));
  tee::AecsServerSecrets secrets;
  PB_PARSE(secrets, secrets_str);

  // Save the storage authentication information and AECS admin public key
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.SetAuth(secrets.storage_auth()));

  // Save the AECS admin public key
  TEE_CHECK_RETURN(InitializeAecsAdmin(secrets.admin()));

  // Seal the new identity which will be saved in untrusted part
  std::string identity_str;
  PB_SERIALIZE(secrets.identity(), &identity_str);
  std::string sealed_identity;
  tee::trusted::Sealer sealer;
  TEE_CHECK_RETURN(sealer.SealSignerData(identity_str, &sealed_identity));
  res.add_result(sealed_identity);

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminRegisterEnclaveService(const std::string& req_str,
                                             std::string* res_str) {
  tee::RegisterEnclaveServiceRequest req;
  tee::RegisterEnclaveServiceResponse res;
  PB_PARSE(req, req_str);

  // Check whether there are special characters in service name
  TEE_CHECK_RETURN(CheckNamevalidity(req.service_name()));

  // Create the service admin authentication object
  tee::AdminAuth service_auth;
  service_auth.set_public_key(req.service_pubkey());
  service_auth.set_password_hash(req.service_password_hash());
  service_auth.set_sequence(0);
  std::string service_auth_str;
  PB_SERIALIZE(service_auth, &service_auth_str);

  // Write the service admin authentication object
  std::string name = req.service_name() + kStorageSuffixServiceAuth;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.Create(name, service_auth_str));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminUnregisterEnclaveService(const std::string& req_str,
                                               std::string* res_str) {
  tee::UnregisterEnclaveServiceRequest req;
  tee::UnregisterEnclaveServiceResponse res;
  PB_PARSE(req, req_str);

  // Remove all the objects who's name is begin with service_name
  // These objects include admin public key and all the secrets
  // Add kServiceSeparator to avoid remove 'abc' for 'ab' case
  std::string name = req.service_name() + kServiceSeparator;
  TEE_CHECK_RETURN(StorageTrustedBridge::GetInstance().Delete(name));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminListEnclaveService(const std::string& req_str,
                                         std::string* res_str) {
  tee::ListEnclaveServiceRequest req;
  tee::ListEnclaveServiceResponse res;
  PB_PARSE(req, req_str);

  // If service_name is not specified, list all service names
  std::string list_pattern = kStorageSuffixServiceAuth;
  if (!req.service_name().empty()) {
    list_pattern = req.service_name() + kStorageSuffixServiceAuth;
  }
  // List all the names of service
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.ListAll(list_pattern, res.mutable_services()));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode AecsProvision(const std::string& req_str, std::string* res_str) {
  tee::AecsProvisionRequest req;
  tee::AecsProvisionResponse res;
  PB_PARSE(req, req_str);

  // Return success only for the first time to set the storage authentication
  TEE_CHECK_RETURN(StorageTrustedBridge::GetInstance().SetAuth(req.auth()));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode AecsReloadIdentity(const std::string& req_str,
                                AdminRemoteCallResponse* res) {
  tee::AecsProvisionRequest req;
  PB_PARSE(req, req_str);

  // Check if need to reload or save the identity backup
  if (req.host_name().empty()) {
    ELOG_WARN("Unknown node name for identity key backup");
    return TEE_SUCCESS;
  }
  // Check whether there are special characters in host name
  TEE_CHECK_RETURN(CheckNamevalidity(req.host_name()));

  std::string identity_name = kStoragePrefixIdentity;
  identity_name.append(req.host_name());

  // Seal the current identity key
  tee::KeyPair& identity = TeeInstance::GetInstance().GetIdentity();
  std::string identity_str;
  PB_SERIALIZE(identity, &identity_str);
  std::string sealed_identity;
  tee::trusted::Sealer sealer;
  TEE_CHECK_RETURN(sealer.SealSignerData(identity_str, &sealed_identity));

  // Check whether the identity key backup exist
  bool identity_exist = false;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.CheckExist(identity_name, &identity_exist));
  if (identity_exist) {
    // Reload the identity key backup from storage
    std::string identity_backup;
    TEE_CHECK_RETURN(storage.GetValue(identity_name, &identity_backup, false));
    if (identity_backup == sealed_identity) {
      ELOG_INFO("No need to reload the same identity key");
    } else {
      ELOG_INFO("Export identity key backup on %s", req.host_name().c_str());
      res->set_sealed_secret(identity_backup);
    }
  } else {
    // Save the identity key backup to storage
    ELOG_INFO("Save the identity key backup on %s", req.host_name().c_str());
    // Don't care about the wrong things, for example, there is already
    // the older identity key backup for the same node, will not overwrite it.
    TEE_CHECK_RETURN(storage.Create(identity_name, sealed_identity, false));
  }

  return TEE_SUCCESS;
}

TeeErrorCode TeeAecsAdminRemoteCall(const std::string& req_str,
                                    std::string* res_str) {
  static std::map<std::string, AecsAdminRemoteFunction> functions = {
      {"RegisterEnclaveService", AecsAdminRegisterEnclaveService},
      {"UnregisterEnclaveService", AecsAdminUnregisterEnclaveService},
      {"ListEnclaveService", AecsAdminListEnclaveService},
      {"AecsProvision", AecsProvision}};
  tee::AdminRemoteCallRequest req;
  tee::AdminRemoteCallResponse res;
  PB_PARSE(req, req_str);

  // If just to get identity public key, return after authentication
  // The untrusted code will append the RA report and public key
  std::string name = req.function_name();
  if (name == "GetIdentityPublicKey") {
    TEE_CHECK_RETURN(VerifyAecsAdmin(req.req_enc()));
    ELOG_DEBUG("Get identity public key, success authentication");
    return TEE_SUCCESS;
  }

  // Decrypt and verify the encrypted request
  std::string freq_str;
  TEE_CHECK_RETURN(
      DecryptAndVerifyRemoteRequest(req.req_enc(), &kAecsAdminAuth, &freq_str));

  // Call the real trusted function
  if (functions.find(name) == functions.end()) {
    ELOG_ERROR("Cannot find function: %s", name.c_str());
    return TEE_ERROR_PBCALL_FUNCTION;
  }
  std::string fres_str;
  AecsAdminRemoteFunction function = functions[name];
  TEE_CHECK_RETURN((*function)(freq_str, &fres_str));
  ELOG_INFO("AecsAdminRemoteCall %s successfully", name.c_str());

  // If the response is empty, then the res_enc will also be empty
  if (!fres_str.empty()) {
    // Encrypt by AECS admin public key and sign by identity private key
    DigitalEnvelopeEncrypted* res_enc = res.mutable_res_enc();
    TEE_CHECK_RETURN(
        EnvelopeEncryptAndSign(kAecsAdminAuth.public_key(), fres_str, res_enc));
  } else {
    ELOG_DEBUG("No response from %s", name.c_str());
  }

  // Get the sealed identity key backup if it existed
  if (name == "AecsProvision") {
    TEE_CHECK_RETURN(AecsReloadIdentity(freq_str, &res));
  }

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminCreateSecret(const std::string& service_name,
                                      const std::string& req_str,
                                      std::string* res_str) {
  tee::CreateEnclaveSecretRequest req;
  tee::CreateEnclaveSecretResponse res;
  PB_PARSE(req, req_str);
  req.mutable_secret()->mutable_spec()->set_service_name(service_name);

  if (req.secret().spec().secret_name().empty()) {
    ELOG_ERROR("There is no secret name");
    return TEE_ERROR_PARAMETERS;
  }
  if (!req.secret().spec().has_type()) {
    ELOG_ERROR("There is no secret type");
    return TEE_ERROR_PARAMETERS;
  }

  // Check whether there are special characters in secret name
  TEE_CHECK_RETURN(CheckNamevalidity(req.secret().spec().secret_name()));

  tee::EnclaveSecretType secret_type = req.secret().spec().type();
  ELOG_INFO("Create enclave secret type: %d", SCAST(int, secret_type));
  if (secret_type == tee::SECRET_TYPE_RSA_KEY_PAIR) {
    // Create the RSA key pair secret
    tee::RsaKeyPair keypair;
    tee::common::RsaCrypto rsa;
    TEE_CHECK_RETURN(rsa.GenerateKeyPair(keypair.mutable_public_key(),
                                         keypair.mutable_private_key()));
    PB_SERIALIZE(keypair, req.mutable_secret()->mutable_data());
  } else if (secret_type == tee::SECRET_TYPE_AES256_KEY) {
    // Create the AES256 key secret
    size_t aes_key_size = tee::common::AesGcmCrypto::get_key_size();
    tee::common::DataBytes aes_key(aes_key_size);
    sgx_status_t sgx_ret = sgx_read_rand(aes_key.data(), aes_key.size());
    if (sgx_ret == SGX_SUCCESS) {
      req.mutable_secret()->mutable_data()->assign(aes_key.GetStr());
    } else {
      ELOG_ERROR("Fail to read SGX rand as AES key");
      return TEE_ERROR_CODE(sgx_ret);
    }
  } else if (secret_type == tee::SECRET_TYPE_IMPORT_DATA) {
    // Check the imported data length
    if (req.secret().data().empty()) {
      ELOG_ERROR("There is no secret data to be imported");
      return TEE_ERROR_PARAMETERS;
    }
    if (req.secret().data().size() > kMaxSecretLength) {
      ELOG_ERROR("The secret size is too large");
      return TEE_ERROR_PARAMETERS;
    }
  } else {
    ELOG_ERROR("Unsupported secret type");
    return TEE_ERROR_PARAMETERS;
  }

  // Write the secret to storage
  std::string secret_str;
  PB_SERIALIZE(req.secret(), &secret_str);
  std::string secret_full_name = req.secret().spec().service_name() +
                                 kStorageSuffixServiceSecret +
                                 req.secret().spec().secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.Create(secret_full_name, secret_str));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminDestroySecret(const std::string& service_name,
                                       const std::string& req_str,
                                       std::string* res_str) {
  tee::DestroyEnclaveSecretRequest req;
  tee::DestroyEnclaveSecretResponse res;
  PB_PARSE(req, req_str);

  if (req.secret_name().empty()) {
    ELOG_ERROR("There is no secret name");
    return TEE_ERROR_PARAMETERS;
  }

  // Delete all the secret objects by secret name
  std::string secret_full_name =
      service_name + kStorageSuffixServiceSecret + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.Delete(secret_full_name));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminListSecret(const std::string& service_name,
                                    const std::string& req_str,
                                    std::string* res_str) {
  tee::ListEnclaveSecretRequest req;
  tee::ListEnclaveSecretResponse res;
  PB_PARSE(req, req_str);

  // If service_name is not specified, list all secrets
  std::string list_pattern = service_name + kStorageSuffixServiceSecret;
  if (!req.secret_name().empty()) {
    list_pattern.append(req.secret_name());
  }

  // Get the names firstly and get secret with data  one by one
  // and return the policies list only finally
  tee::StorageListAllResponse storage_res;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.ListAll(list_pattern, &storage_res));
  for (int i = 0; i < storage_res.names_size(); i++) {
    std::string value;
    storage.GetValue(storage_res.names()[i], &value);
    tee::EnclaveSecret secret;
    PB_PARSE(secret, value);
    res.add_secrets()->CopyFrom(secret.spec());
  }

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeServiceAdminRemoteCall(const std::string& req_str,
                                       std::string* res_str) {
  static std::map<std::string, ServiceAdminRemoteFunction> functions = {
      {"CreateSecret", ServiceAdminCreateSecret},
      {"DestroySecret", ServiceAdminDestroySecret},
      {"ListSecret", ServiceAdminListSecret}};
  static size_t admin_remote_call_sequence = 0;

  tee::AdminRemoteCallRequest req;
  tee::AdminRemoteCallResponse res;
  PB_PARSE(req, req_str);

  std::string function_name = req.function_name();
  std::string service_name = req.req_enc().aes_cipher().aad();
  ELOG_INFO("ServiceAdminRemoteCall: function:%s", function_name.c_str());
  ELOG_INFO("ServiceAdminRemoteCall: service:%s", service_name.c_str());

  // Get the service administrator authentication settings from storage
  std::string service_auth_str;
  std::string service_auth_name = service_name + kStorageSuffixServiceAuth;
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.GetValue(service_auth_name, &service_auth_str));
  tee::AdminAuth service_auth;
  PB_PARSE(service_auth, service_auth_str);

  // If just to get identity public key, return after authentication
  // The untrusted code will append the RA report and public key
  if (function_name == "GetIdentityPublicKey") {
    TEE_CHECK_RETURN(
        VerifyAdminSignature(service_auth.public_key(), req.req_enc()));
    ELOG_DEBUG("Get identity public key, success authentication");
    return TEE_SUCCESS;
  }

  // Decrypt and verify the encrypted request
  std::string freq_str;
  TEE_CHECK_RETURN(
      DecryptAndVerifyRemoteRequest(req.req_enc(), &service_auth, &freq_str));
  TEE_CHECK_RETURN(storage.Update(service_auth_name, service_auth_str));

  // Call the real trusted function
  if (functions.find(function_name) == functions.end()) {
    ELOG_ERROR("Cannot find function: %s", function_name.c_str());
    return TEE_ERROR_PBCALL_FUNCTION;
  }
  std::string fres_str;
  ServiceAdminRemoteFunction function = functions[function_name];
  TEE_CHECK_RETURN((*function)(service_name, freq_str, &fres_str));
  ELOG_INFO("ServiceAdminRemoteCall %s successfully", function_name.c_str());

  // If the response is empty, then the res_enc will also be empty
  if (!fres_str.empty()) {
    // Encrypt by AECS admin public key and sign by identity private key
    DigitalEnvelopeEncrypted* res_enc = res.mutable_res_enc();
    TEE_CHECK_RETURN(
        EnvelopeEncryptAndSign(service_auth.public_key(), fres_str, res_enc));
  } else {
    ELOG_DEBUG("No response from %s", function_name.c_str());
  }

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeGetEnclaveSecret(const std::string& req_str,
                                 std::string* res_str) {
  tee::GetEnclaveSecretRequest req;
  tee::GetEnclaveSecretResponse res;
  PB_PARSE(req, req_str);

  // Get the enclave secret keys by service and secret name
  std::string secret_str;
  std::string secret_full_name =
      req.service_name() + kStorageSuffixServiceSecret + req.secret_name();
  StorageTrustedBridge& storage = StorageTrustedBridge::GetInstance();
  TEE_CHECK_RETURN(storage.GetValue(secret_full_name, &secret_str));

  // Check the service and secret name in secret
  tee::EnclaveSecret secret;
  PB_PARSE(secret, secret_str);
  if (req.service_name() != secret.spec().service_name()) {
    ELOG_ERROR("Service name does not match what in the secret spec");
    return TEE_ERROR_UNEXPECTED;
  }
  if (req.secret_name() != secret.spec().secret_name()) {
    ELOG_ERROR("Secret name does not match what in the secret spec");
    return TEE_ERROR_UNEXPECTED;
  }

  // Verify the enclave service IAS report by the secret policy
  const tee::RaReportAuthentication& auth = req.auth_ra_report();
  TEE_CHECK_RETURN(VerifySecretPolicy(auth, secret.spec().policy()));

  // Encrypt the secret by the enclave service public key
  TEE_CHECK_RETURN(EnvelopeEncryptAndSign(
      auth.public_key(), secret.data(), res.mutable_secret_enc()));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode TeeInitializeAecsAdmin(const std::string& req_str,
                                    std::string* res_str) {
  tee::AecsAdminInitializeRequest req;
  tee::AecsAdminInitializeResponse res;
  PB_PARSE(req, req_str);

  if (!kAecsAdminAuth.public_key().empty()) {
    ELOG_ERROR("AECS administrator public key already exists");
    return TEE_ERROR_UNEXPECTED;
  }

  TEE_CHECK_RETURN(InitializeAecsAdmin(req.admin()));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode RegisterTrustedPbFunctionsEx() {
  ELOG_DEBUG("Register application trusted functions");
  ADD_TRUSTED_PBCALL_FUNCTION(TeeGetRemoteSecret);
  ADD_TRUSTED_PBCALL_FUNCTION(TeeUnpackRemoteSecret);
  ADD_TRUSTED_PBCALL_FUNCTION(TeeAecsAdminRemoteCall);
  ADD_TRUSTED_PBCALL_FUNCTION(TeeServiceAdminRemoteCall);
  ADD_TRUSTED_PBCALL_FUNCTION(TeeGetEnclaveSecret);
  ADD_TRUSTED_PBCALL_FUNCTION(TeeInitializeAecsAdmin);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
