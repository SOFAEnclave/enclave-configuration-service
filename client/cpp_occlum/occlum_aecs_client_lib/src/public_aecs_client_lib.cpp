#include "public_aecs_client_lib.h"
#include <string>

#include "aecs.pb.h"
#include "attestation/common/rsa.h"
#include "unified_attestation/ua_untrusted.h"
#include "untrusted/untrusted_aecs_client.h"

TeeErrorCode VerifyAecsEnclave(
    const kubetee::UnifiedAttestationAuthReport& auth,
    const std::string& json_policy) {
  // Empty policy means to ignore the aecs server report varification
  if (json_policy.empty()) {
    ELOG_WARN("Ignore the AECS server report verification!!!");
    return TEE_SUCCESS;
  }

  kubetee::UnifiedAttestationPolicy policy;
  JSON2PB(json_policy, &policy);
  TEE_CHECK_RETURN(UaVerifyAuthReport(auth, policy));
  return TEE_SUCCESS;
}

TeeErrorCode aecs_client_get_public_secret_to_file(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& save_file_name) {
  std::string secret_public_str;
  TEE_CHECK_RETURN(aecs_client_get_public_secret(
      aecs_server_endpoint, aecs_server_policy, secret_service, secret_name,
      &secret_public_str));
  // Save the secret string into local file system
  // For occlum,  it should be secure filesytem to avoid secret leak
  using kubetee::utils::FsWriteString;
  TEE_CHECK_RETURN(FsWriteString(save_file_name, secret_public_str));

  return TEE_SUCCESS;
}

TeeErrorCode aecs_client_get_public_secret(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    std::string* secret) {
  // Create the authentication remote attestation report
  aecs::untrusted::AecsClient aecs_client(aecs_server_endpoint);
  kubetee::GetEnclaveSecretPublicRequest req;
  kubetee::GetEnclaveSecretPublicResponse res;

  req.set_service_name(secret_service);
  req.set_secret_name(secret_name);
  TEE_CHECK_RETURN(aecs_client.GetEnclaveSecretPublic(req, &res));

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(res.auth_ra_report(), aecs_server_policy));

  const std::string& verify_pubkey = res.auth_ra_report().pem_public_key();

  kubetee::common::DataBytes sig_b64(res.signature_b64());
  std::string signature = sig_b64.FromBase64().GetStr();

  // Verify the signature
  TEE_CHECK_RETURN(kubetee::common::RsaCrypto::Verify(
      verify_pubkey, res.secret_public(), signature));

  *secret = res.secret_public();

  return TEE_SUCCESS;
}

#ifdef __cplusplus
extern "C" {
#endif

int aecs_client_get_public_secret_and_save_file(
    const char* aecs_server_endpoint,
    const char* aecs_server_policy,
    const char* secret_service,
    const char* secret_name,
    const char* save_file_name) {
  TEE_CHECK_RETURN(aecs_client_get_public_secret_to_file(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), SAFESTR(save_file_name)));
  return 0;
}

int aecs_client_get_public_secret_by_buffer(const char* aecs_server_endpoint,
                                            const char* aecs_server_policy,
                                            const char* secret_service,
                                            const char* secret_name,
                                            const char* secret_outbuf,
                                            int* secret_outbuf_len) {
  TEE_CHECK_VALIDBUF(secret_outbuf, secret_outbuf_len);

  std::string secret_str;
  TEE_CHECK_RETURN(aecs_client_get_public_secret(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), &secret_str));
  if (*secret_outbuf_len <= secret_str.size()) {
    return TEE_ERROR_SMALL_BUFFER;
  }

  memcpy(RCCAST(void*, secret_outbuf), secret_str.data(), secret_str.size());
  *secret_outbuf_len = secret_str.size();
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
