#include <memory>
#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"

#include "aecs.pb.h"
#include "untrusted/untrusted_aecs_client.h"

#include "occlum_aecs_client_lib.h"
#include "public_aecs_client_lib.h"

#include "serviceadmin/serviceadmin_secret_policy.h"

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
    const std::string& secret_policy,
    const std::string& nonce,
    const std::string& save_file_name) {
  std::string secret_str;
  TEE_CHECK_RETURN(aecs_client_get_secret(
      aecs_server_endpoint, aecs_server_policy, secret_service, secret_name,
      secret_policy, nonce, &secret_str));
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
                                    const std::string& secret_policy,
                                    const std::string& nonce,
                                    std::string* secret_str) {
  kubetee::GetEnclaveSecretRequest req;
  kubetee::GetEnclaveSecretResponse res;

  // Create the authentication remote attestation report
  kubetee::UnifiedAttestationAuthReport* auth = req.mutable_auth_ra_report();
  kubetee::attestation::UaReportGenerationParameters param;
  param.tee_identity = kDummyTeeIdentity;
  param.report_type = kUaReportTypePassport;
  TEE_CHECK_RETURN(UaGenerateAuthReport(&param, auth));

  // Get secret from AECS server
  if (secret_service.empty()) {
    req.set_service_name(kTaServiceName);
  } else {
    req.set_service_name(secret_service);
  }
  req.set_secret_name(secret_name);
  req.set_nonce(nonce);
  aecs::untrusted::AecsClient aecs_client(aecs_server_endpoint);
  TEE_CHECK_RETURN(aecs_client.GetEnclaveSecret(req, &res));

  // Verify the remote AECS enclave RA report
  TEE_CHECK_RETURN(VerifyAecsEnclave(res.auth_ra_report(), aecs_server_policy));

  // Decrypt and verify the digital envelope encrypted identity keys
  std::string enclave_secret_str;
  kubetee::EnclaveSecret secret;
  TEE_CHECK_RETURN(EnvelopeDecryptAndVerify(res, nonce, &enclave_secret_str));
  JSON2PB(enclave_secret_str, &secret);

  // Verify secret policy if necessary
  if (!secret_policy.empty() && secret_policy != "{}") {
    const kubetee::UnifiedAttestationPolicy& policy =
        secret.spec().policy().policy();
    kubetee::UnifiedAttestationPolicy expected_policy;
    JSON2PB(secret_policy, &expected_policy);
    TEE_CHECK_RETURN(UaVerifyPolicy(policy, expected_policy));
  }

  secret_str->assign(secret.data());
  return TEE_SUCCESS;
}

TeeErrorCode aecs_client_create_secret(const std::string& aecs_server_endpoint,
                                       const std::string& aecs_server_policy,
                                       const std::string& secret_policy_file) {
  kubetee::CreateTaSecretRequest req;
  kubetee::CreateTaSecretResponse res;

  // Create the authentication remote attestation report
  kubetee::UnifiedAttestationAuthReport* auth = req.mutable_auth_ra_report();
  kubetee::attestation::UaReportGenerationParameters param;
  param.tee_identity = kDummyTeeIdentity;
  param.report_type = kUaReportTypePassport;
  TEE_CHECK_RETURN(UaGenerateAuthReport(&param, auth));

  // Parse the secret policies from yaml file
  kubetee::SecretsParseResult result;
  aecs::client::SecretPolicyParser policy_parser(secret_policy_file);
  TEE_CHECK_RETURN(policy_parser.Parse(&result));
  aecs::untrusted::AecsClient aecs_client(aecs_server_endpoint);
  TeeErrorCode last_err = TEE_SUCCESS;
  for (int i = 0; i < result.secrets_size(); i++) {
    std::string secret_name = result.secrets()[i].spec().secret_name();
    TEE_LOG_INFO("Create the secret[%d]: %s", i, secret_name.c_str());
    kubetee::EnclaveSecret* secret = req.mutable_secret();
    secret->CopyFrom(result.secrets()[i]);
    secret->mutable_spec()->mutable_policy()->mutable_policy()->Clear();
    int ret = aecs_client.CreateTaSecret(req, &res);
    if (ret != TEE_SUCCESS) {
      TEE_LOG_ERROR("Fail to create secret: %s", secret_name.c_str());
      last_err = ret;
    }
  }

  return last_err;
}

TeeErrorCode aecs_client_destroy_secret(const std::string& aecs_server_endpoint,
                                        const std::string& aecs_server_policy,
                                        const std::string& secret_name) {
  kubetee::DestroyTaSecretRequest req;
  kubetee::DestroyTaSecretResponse res;

  // Create the authentication remote attestation report
  kubetee::UnifiedAttestationAuthReport* auth = req.mutable_auth_ra_report();
  kubetee::attestation::UaReportGenerationParameters param;
  param.tee_identity = kDummyTeeIdentity;
  param.report_type = kUaReportTypePassport;
  TEE_CHECK_RETURN(UaGenerateAuthReport(&param, auth));

  // Destroy the trusted application bound secret
  req.set_secret_name(secret_name);
  aecs::untrusted::AecsClient aecs_client(aecs_server_endpoint);
  TEE_CHECK_RETURN(aecs_client.DestroyTaSecret(req, &res));

  return TEE_SUCCESS;
}

#ifdef __cplusplus
extern "C" {
#endif

/// Get Secret for TEE application and Save to file
int aecs_client_get_secret_file(const char* aecs_server_endpoint,
                                const char* aecs_server_policy,
                                const char* secret_service,
                                const char* secret_name,
                                const char* secret_policy,
                                const char* nonce,
                                const char* save_file_name) {
  TEE_CHECK_RETURN(aecs_client_get_secret_to_file(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), SAFESTR(secret_policy),
      SAFESTR(nonce), SAFESTR(save_file_name)));
  return 0;
}

int aecs_client_get_secret_and_save_file(const char* aecs_server_endpoint,
                                         const char* aecs_server_policy,
                                         const char* secret_service,
                                         const char* secret_name,
                                         const char* secret_policy,
                                         const char* nonce,
                                         const char* save_file_name) {
  TEE_FUNCTION_DEPRECATED();
  return aecs_client_get_secret_file(aecs_server_endpoint, aecs_server_policy,
                                     secret_service, secret_name, "", nonce,
                                     save_file_name);
}

/// Get Secret for TEE application and return it buffer
int aecs_client_get_secret_buffer(const char* aecs_server_endpoint,
                                  const char* aecs_server_policy,
                                  const char* secret_service,
                                  const char* secret_name,
                                  const char* secret_policy,
                                  const char* nonce,
                                  char* secret_outbuf,
                                  int* secret_outbuf_len) {
  TEE_CHECK_VALIDBUF(secret_outbuf, secret_outbuf_len);

  std::string secret_str;
  TEE_CHECK_RETURN(aecs_client_get_secret(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), SAFESTR(secret_policy),
      SAFESTR(nonce), &secret_str));
  if (*secret_outbuf_len <= secret_str.size()) {
    return TEE_ERROR_SMALL_BUFFER;
  }

  memcpy(RCAST(void*, secret_outbuf), secret_str.data(), secret_str.size());
  *secret_outbuf_len = secret_str.size();
  return TEE_SUCCESS;
}

int aecs_client_get_secret_by_buffer(const char* aecs_server_endpoint,
                                     const char* aecs_server_policy,
                                     const char* secret_service,
                                     const char* secret_name,
                                     const char* nonce,
                                     char* secret_outbuf,
                                     int* secret_outbuf_len) {
  TEE_FUNCTION_DEPRECATED();
  return aecs_client_get_secret_buffer(aecs_server_endpoint, aecs_server_policy,
                                       secret_service, secret_name, "", nonce,
                                       secret_outbuf, secret_outbuf_len);
}

/// Create Trusted application bound secret
int aecs_client_create_ta_secret(const char* aecs_server_endpoint,
                                 const char* aecs_server_policy,
                                 const char* secret_policy_file) {
  TEE_CHECK_RETURN(aecs_client_create_secret(SAFESTR(aecs_server_endpoint),
                                             SAFESTR(aecs_server_policy),
                                             SAFESTR(secret_policy_file)));
  return 0;
}

/// Destroy Trusted application bound secret
int aecs_client_destroy_ta_secret(const char* aecs_server_endpoint,
                                  const char* aecs_server_policy,
                                  const char* secret_name) {
  TEE_CHECK_RETURN(aecs_client_destroy_secret(SAFESTR(aecs_server_endpoint),
                                              SAFESTR(aecs_server_policy),
                                              SAFESTR(secret_name)));
  return 0;
}

#ifdef __cplusplus
}
#endif
