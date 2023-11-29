#include <memory>
#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"

#include "aecs.pb.h"
#include "untrusted/untrusted_aecs_client.h"

#include "occlum_aecs_client_lib.h"
#include "public_aecs_client_lib.h"

#include "serviceadmin/serviceadmin_secret_policy.h"

static TeeErrorCode SignB64(const std::string& msg, std::string* sig_b64) {
  // Sign the msg string and return the signature in base64 format
  kubetee::common::AsymmetricCrypto ac;
  const std::string& private_key = UakPrivate();
  bool sm_mode = ac.isSmMode(private_key);
  std::string signature;
  TEE_CHECK_RETURN(ac.Sign(private_key, msg, &signature, sm_mode));
  kubetee::common::DataBytes signature_b64(signature);
  sig_b64->assign(signature_b64.ToBase64().GetStr());
  return TEE_SUCCESS;
}

static TeeErrorCode AddRequestAuthReport(const std::string& hex_user_data,
                                         kubetee::TaRemoteCallRequest* req) {
  // Create the authentication remote attestation report
  kubetee::UnifiedAttestationAuthReport* auth = req->mutable_auth_report();
  kubetee::attestation::UaReportGenerationParameters param;
  param.tee_identity = kDummyTeeIdentity;
  param.report_type = kUaReportTypePassport;
  param.others.set_hex_user_data(hex_user_data);
  TEE_CHECK_RETURN(UaGenerateAuthReport(&param, auth));
  return TEE_SUCCESS;
}

static TeeErrorCode VerifyAecsSignature(
    const std::string& public_key, const kubetee::TaRemoteCallResponse& res) {
  kubetee::common::AsymmetricCrypto ac;
  kubetee::common::DataBytes res_sig_b64(res.signature_b64());
  TEE_CHECK_RETURN(ac.Verify(public_key, res.res_json(),
                             res_sig_b64.FromBase64().GetStr(),
                             ac.isSmMode(public_key)));
  return TEE_SUCCESS;
}

static TeeErrorCode VerifyResponseNonce(const std::string& req_nonce,
                                        const std::string& res_nonce) {
  if (!req_nonce.empty() && res_nonce != req_nonce) {
    ELOG_ERROR("Nonce mismatch in response");
    ELOG_DEBUG("  Expected: %s", req_nonce.c_str());
    ELOG_DEBUG("  Actual: %s", res_nonce.c_str());
    return AECS_ERROR_CLIENT_SECRET_NONCE_MISMATCHED;
  }
  return TEE_SUCCESS;
}

static TeeErrorCode EnvelopeDecryptAndVerify(
    const std::string& verify_pubkey,
    const kubetee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  // Always decrypt cipher by identity private key
  const std::string& dec_prvkey = UakPrivate();
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(dec_prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

static TeeErrorCode TaRemoteCall(const std::string& aecs_server_endpoint,
                                 const std::string& aecs_server_policy,
                                 const std::string& hex_user_data,
                                 const std::string& function_name,
                                 const google::protobuf::Message& request,
                                 google::protobuf::Message* response,
                                 std::string* server_public_key) {
  // Prepare the remotecall request
  kubetee::TaRemoteCallRequest req;
  kubetee::TaRemoteCallResponse res;
  req.set_function_name(function_name);
  PB2JSON(request, req.mutable_req_json());
  TEE_CHECK_RETURN(SignB64(req.req_json(), req.mutable_signature_b64()));
  TEE_CHECK_RETURN(AddRequestAuthReport(hex_user_data, &req));

  // Destroy the trusted application bound secret
  aecs::untrusted::AecsClient aecs_client(aecs_server_endpoint);
  TEE_CHECK_RETURN(aecs_client.TaRemoteCall(req, &res));

  // Verify the remote AECS enclave RA report and response signature
  const std::string& server_pubkey = res.auth_report().pem_public_key();
  TEE_CHECK_RETURN(VerifyAecsEnclave(res.auth_report(), aecs_server_policy));
  TEE_CHECK_RETURN(VerifyAecsSignature(server_pubkey, res));

  // output the function response
  JSON2PB(res.res_json(), response);

  // output server public key if neccessary
  if (server_public_key) {
    server_public_key->assign(server_pubkey);
  }
  return TEE_SUCCESS;
}

TeeErrorCode aecs_client_get_secret_to_file(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& secret_policy,
    const std::string& hex_user_data,
    const std::string& nonce,
    const std::string& save_file_name) {
  std::string secret_str;
  TEE_CHECK_RETURN(aecs_client_get_secret(
      aecs_server_endpoint, aecs_server_policy, secret_service, secret_name,
      secret_policy, hex_user_data, nonce, &secret_str));
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
                                    const std::string& hex_user_data,
                                    const std::string& nonce,
                                    std::string* secret_str) {
  // Prepare TaGetSecretRequest
  kubetee::TaGetSecretRequest req_get;
  kubetee::TaGetSecretResponse res_get;
  req_get.set_service_name(secret_service);
  req_get.set_secret_name(secret_name);
  req_get.set_nonce(nonce);
  if (secret_service.empty()) {
    req_get.set_service_name(kTaServiceName);
  }

  // Call the remote function to get secret
  std::string server_pubkey;
  TEE_CHECK_RETURN(TaRemoteCall(aecs_server_endpoint, aecs_server_policy,
                                hex_user_data, "TaGetSecret", req_get, &res_get,
                                &server_pubkey));

  // Verify the nonce in response if there is nonce in request
  TEE_CHECK_RETURN(VerifyResponseNonce(nonce, res_get.nonce()));

  // Decrypt and verify the digital envelope encrypted identity keys
  std::string enclave_secret_str;
  kubetee::EnclaveSecret secret;
  const kubetee::DigitalEnvelopeEncrypted& env = res_get.secret_enc();
  TEE_CHECK_RETURN(
      EnvelopeDecryptAndVerify(server_pubkey, env, &enclave_secret_str));
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
                                       const std::string& secret_policy_file,
                                       const std::string& hex_user_data,
                                       const std::string& nonce) {
  // Parse the secret policies from yaml file
  kubetee::SecretsParseResult result;
  aecs::client::SecretPolicyParser policy_parser(secret_policy_file);
  TEE_CHECK_RETURN(policy_parser.Parse(&result));
  TeeErrorCode last_err = TEE_SUCCESS;
  for (int i = 0; i < result.secrets_size(); i++) {
    kubetee::TaCreateSecretRequest req_create;
    kubetee::TaCreateSecretResponse res_create;
    req_create.set_nonce(nonce);

    std::string secret_name = result.secrets()[i].spec().secret_name();
    ELOG_INFO("Create the secret[%d]: %s", i, secret_name.c_str());
    kubetee::EnclaveSecret* secret = req_create.mutable_secret();
    secret->CopyFrom(result.secrets()[i]);
    secret->mutable_spec()->mutable_policy()->mutable_policy()->Clear();
    if (!secret->data().empty()) {
      // Because the request string only has integrity protection
      // Import data will result in data leakage
      ELOG_ERROR("Cannot import TA bound secret: %s", secret_name.c_str());
      last_err = AECS_ERROR_SECRET_CREATE_DATA_NOT_SUPPORT;
      continue;
    }

    // Call the remote function to create secret
    TeeErrorCode ret =
        TaRemoteCall(aecs_server_endpoint, aecs_server_policy, hex_user_data,
                     "TaCreateSecret", req_create, &res_create, nullptr);
    if (ret != TEE_SUCCESS) {
      ELOG_ERROR("Fail to create secret: %s", secret_name.c_str());
      last_err = ret;
      continue;
    }

    // Verify the nonce in response if there is nonce in request
    ret = VerifyResponseNonce(nonce, res_create.nonce());
    if (ret != TEE_SUCCESS) {
      ELOG_ERROR("Create secret %s, nonce mismatch", secret_name.c_str());
      last_err = ret;
      continue;
    }
  }

  return last_err;
}

TeeErrorCode aecs_client_destroy_secret(const std::string& aecs_server_endpoint,
                                        const std::string& aecs_server_policy,
                                        const std::string& secret_name,
                                        const std::string& hex_user_data,
                                        const std::string& nonce) {
  // Prepare TaGetSecretRequest
  kubetee::TaDestroySecretRequest req_destroy;
  kubetee::TaDestroySecretResponse res_destroy;
  req_destroy.set_secret_name(secret_name);
  req_destroy.set_nonce(nonce);

  // Call the remote function to destroy secret
  TEE_CHECK_RETURN(TaRemoteCall(aecs_server_endpoint, aecs_server_policy,
                                hex_user_data, "TaDestroySecret", req_destroy,
                                &res_destroy, nullptr));

  // Verify the nonce in response if there is nonce in request
  TEE_CHECK_RETURN(VerifyResponseNonce(nonce, res_destroy.nonce()));

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
                                const char* hex_user_data,
                                const char* nonce,
                                const char* save_file_name) {
  TEE_CHECK_RETURN(aecs_client_get_secret_to_file(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), SAFESTR(secret_policy),
      SAFESTR(hex_user_data), SAFESTR(nonce), SAFESTR(save_file_name)));
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
                                     secret_service, secret_name, "", "", nonce,
                                     save_file_name);
}

/// Get Secret for TEE application and return it buffer
int aecs_client_get_secret_buffer(const char* aecs_server_endpoint,
                                  const char* aecs_server_policy,
                                  const char* secret_service,
                                  const char* secret_name,
                                  const char* secret_policy,
                                  const char* hex_user_data,
                                  const char* nonce,
                                  char* secret_outbuf,
                                  int* secret_outbuf_len) {
  TEE_CHECK_VALIDBUF(secret_outbuf, secret_outbuf_len);

  std::string secret_str;
  TEE_CHECK_RETURN(aecs_client_get_secret(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_service), SAFESTR(secret_name), SAFESTR(secret_policy),
      SAFESTR(hex_user_data), SAFESTR(nonce), &secret_str));
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
                                       secret_service, secret_name, "", "",
                                       nonce, secret_outbuf, secret_outbuf_len);
}

/// Create Trusted application bound secret
int aecs_client_create_ta_secret(const char* aecs_server_endpoint,
                                 const char* aecs_server_policy,
                                 const char* secret_policy_file,
                                 const char* hex_user_data,
                                 const char* nonce) {
  TEE_CHECK_RETURN(aecs_client_create_secret(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_policy_file), SAFESTR(hex_user_data), SAFESTR(nonce)));
  return 0;
}

/// Destroy Trusted application bound secret
int aecs_client_destroy_ta_secret(const char* aecs_server_endpoint,
                                  const char* aecs_server_policy,
                                  const char* secret_name,
                                  const char* hex_user_data,
                                  const char* nonce) {
  TEE_CHECK_RETURN(aecs_client_destroy_secret(
      SAFESTR(aecs_server_endpoint), SAFESTR(aecs_server_policy),
      SAFESTR(secret_name), SAFESTR(hex_user_data), SAFESTR(nonce)));
  return 0;
}

#ifdef __cplusplus
}
#endif
