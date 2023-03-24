#include <memory>
#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"

#include "aecs.pb.h"
#include "untrusted/untrusted_aecs_client.h"

#include "occlum_aecs_client_lib.h"
#include "public_aecs_client_lib.h"

static TeeErrorCode EnvelopeDecryptAndVerify(
    const kubetee::GetEnclaveSecretResponse& secret,
    std::string nonce,
    std::string* plain) {
  // If there is nonce, it will be included as envelope AES cipher add
  const std::string& actual_nonce = secret.secret_enc().aes_cipher().aad();
  if (!nonce.empty() && nonce != actual_nonce) {
    TEE_LOG_ERROR("Nonce mismatch when client get secret");
    TEE_LOG_DEBUG("  Expected: %s", nonce.c_str());
    TEE_LOG_DEBUG("  Actual: %s", actual_nonce.c_str());
    return AECS_ERROR_CLIENT_SECRET_NONCE_MISMATCHED;
  }

  // Always decrypt cipher by identity private key
  const std::string& dec_prvkey = UakPrivate();
  const std::string& verify_pubkey = secret.auth_ra_report().pem_public_key();
  const kubetee::DigitalEnvelopeEncrypted& env = secret.secret_enc();
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(dec_prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode aecs_client_get_secret_to_file(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& nonce,
    const std::string& save_file_name) {
  std::string secret_str;
  TEE_CHECK_RETURN(aecs_client_get_secret(aecs_server_endpoint,
                                          aecs_server_policy, secret_service,
                                          secret_name, nonce, &secret_str));
  // Save the secret string into local file system
  // For occlum,  it should be secure filesytem to avoid secret leak
  using kubetee::utils::FsWriteString;
  TEE_CHECK_RETURN(FsWriteString(save_file_name, secret_str));

  return TEE_SUCCESS;
}

TeeErrorCode aecs_client_get_secret(const std::string& aecs_server_endpoint,
                                    const std::string& aecs_server_policy,
                                    const std::string& secret_service,
                                    const std::string& secret_name,
                                    const std::string& nonce,
                                    std::string* secret_str) {
  // Create the authentication remote attestation report
  aecs::untrusted::AecsClient aecs_client(aecs_server_endpoint);
  kubetee::GetEnclaveSecretRequest req;
  kubetee::GetEnclaveSecretResponse res;
  kubetee::UnifiedAttestationAuthReport* auth = req.mutable_auth_ra_report();
  kubetee::attestation::UaReportGenerationParameters param;
  param.tee_identity = kOcclumDummyTeeIdentity;
  param.report_type = kUaReportTypePassport;
  TEE_CHECK_RETURN(UaGenerateAuthReport(&param, auth));
  req.set_service_name(secret_service);
  req.set_secret_name(secret_name);
  req.set_nonce(nonce);
  TEE_CHECK_RETURN(aecs_client.GetEnclaveSecret(req, &res));

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(res.auth_ra_report(), aecs_server_policy));

  // Decrypt and verify the digital envelope encrypted identity keys
  TEE_CHECK_RETURN(EnvelopeDecryptAndVerify(res, nonce, secret_str));

  return TEE_SUCCESS;
}

#ifdef __cplusplus
extern "C" {
#endif

int aecs_client_get_secret_and_save_file(const char* aecs_server_endpoint,
                                         const char* aecs_server_policy,
                                         const char* secret_service,
                                         const char* secret_name,
                                         const char* nonce,
                                         const char* save_file_name) {
  TEE_CHECK_RETURN(aecs_client_get_secret_to_file(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), SAFESTR(nonce),
      SAFESTR(save_file_name)));
  return 0;
}

int aecs_client_get_secret_by_buffer(const char* aecs_server_endpoint,
                                     const char* aecs_server_policy,
                                     const char* secret_service,
                                     const char* secret_name,
                                     const char* nonce,
                                     char* secret_outbuf,
                                     int* secret_outbuf_len) {
  TEE_CHECK_VALIDBUF(secret_outbuf, secret_outbuf_len);

  std::string secret_str;
  TEE_CHECK_RETURN(aecs_client_get_secret(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), SAFESTR(nonce),
      &secret_str));
  if (*secret_outbuf_len <= secret_str.size()) {
    return TEE_ERROR_SMALL_BUFFER;
  }

  memcpy(RCAST(void*, secret_outbuf), secret_str.data(), secret_str.size());
  *secret_outbuf_len = secret_str.size();
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
