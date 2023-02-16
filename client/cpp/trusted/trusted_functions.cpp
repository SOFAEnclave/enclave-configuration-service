#include <map>
#include <string>

#include "./sgx_trts.h"

#include "unified_attestation/ua_trusted.h"

#include "trusted/trusted_functions.h"

#include "./aecs.pb.h"
#include "./enclave_t.h"

using kubetee::attestation::TeeInstance;

#ifdef __cplusplus
extern "C" {
#endif

static TeeErrorCode VerifyAecsEnclave(
    const kubetee::UnifiedAttestationAuthReport& auth) {
  // Verify the remote enclave MRSIGNER and PRODID
  kubetee::UnifiedAttestationPolicy policy;
  kubetee::UnifiedAttestationAttributes* attr = policy.add_main_attributes();
  TeeInstance& ti = TeeInstance::GetInstance();
  // Assume the AECS enclcave is signed by the same signing key
  // and use the same service provider ID
  attr->set_hex_signer(ti.GetEnclaveInfo().hex_signer());
  attr->set_hex_ta_measurement("");
  attr->set_hex_spid(ti.GetEnclaveInfo().hex_spid());
  attr->set_hex_prod_id("");
  attr->set_str_min_isvsvn("0");
  attr->set_hex_user_data("");
  TEE_CHECK_RETURN(UaVerifyAuthReport(auth, policy));
  return TEE_SUCCESS;
}

static TeeErrorCode EnvelopeEncryptAndSign(
    const std::string& encrypt_pubkey,
    const std::string& plain,
    kubetee::DigitalEnvelopeEncrypted* env) {
  // Always sign plain by identity private key
  TeeInstance& ti = TeeInstance::GetInstance();
  const kubetee::AsymmetricKeyPair& identity = ti.GetIdentity();

  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(envelope.Sign(identity.private_key(), plain, env));
  return TEE_SUCCESS;
}

static TeeErrorCode EnvelopeDecryptAndVerify(
    const std::string& verify_pubkey,
    const kubetee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  // Always decrypt cipher by identity private key
  TeeInstance& ti = TeeInstance::GetInstance();
  std::string prvkey = ti.GetIdentity().private_key();

  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
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

TeeErrorCode TeeImportSecret(const std::string& req_str, std::string* res_str) {
  kubetee::GetEnclaveSecretResponse req;
  kubetee::UnifiedFunctionGenericResponse res;
  JSON2PB(req_str, &req);

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(req.auth_ra_report()));

  // Decrypt and verify the digital envelope encrypted identity keys
  std::string secret_str;
  TEE_CHECK_RETURN(EnvelopeDecryptAndVerify(
      req.auth_ra_report().pem_public_key(), req.secret_enc(), &secret_str));

  kubetee::common::DataBytes data(secret_str);
  // This is a test enclave, in the formal enclave, we cannot leak secret
  tee_printf("[Secret]%s\n", data.ToHexStr().GetStr().c_str());

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode RegisterTrustedUnifiedFunctionsEx() {
  ELOG_DEBUG("Register application trusted functions");
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeImportSecret);
  ADD_TRUSTED_UNIFIED_FUNCTION(TeeInitializeAecsEnclave);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
