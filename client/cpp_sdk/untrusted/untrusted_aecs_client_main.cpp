#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "untrusted/untrusted_aecs_client.h"

#include "aecs/error.h"
#include "aecs/untrusted_enclave.h"

#include "gflags/gflags.h"

#include "./aecs.pb.h"

#include "serviceadmin/serviceadmin_secret_policy.h"

using aecs::untrusted::AecsClient;

#define ENCLAVE_FILENAME "/usr/lib64/aecs_client_test_enclave.signed.so"

static const char kVersion[] = "v1";
static const char kUsage[] =
    "aecs_client_test_service --action <sub-command> [option-flags ...]\n"
    "\nSub Commands:\n"
    "\tcreate      Creates trusted application bound secrets by yaml conf\n"
    "\tdestroy     Destroy a trusted application bound secret by name\n"
    "\tget         Get secret created by serivceadmin or TA\n";

// Define the command line options
DEFINE_string(action, "", "action name [create/destroy/get]");
DEFINE_string(service, kTaServiceName, "service name");
DEFINE_string(secret, "", "secret name");
DEFINE_string(policy, "", "Yaml policy file for creating secrets");
DEFINE_string(enclave, "", "Special the path of enclave so file");

#define CHECK_FLAGS(f, m)                      \
  do {                                         \
    if (f.empty()) {                           \
      TEE_LOG_ERROR(m);                        \
      return AECS_ERROR_PARAMETER_FLAGS_EMPTT; \
    }                                          \
  } while (0)

static const char kTestNonce[] = "test-only-nonce-string";

//=============================================================
// The action handlers
//=============================================================
static TeeErrorCode AddEnclaveSeriveAuth(
    EnclaveInstance* enclave, kubetee::UnifiedAttestationAuthReport* auth) {
  const std::string hex_user_data = "313233";  // for test only
  TEE_CHECK_RETURN(enclave->CreateRaReport(hex_user_data));
  auth->CopyFrom(enclave->GetLocalAuthReport());
  return TEE_SUCCESS;
}

TeeErrorCode DoTaCreateSecret(AecsClient* aecs_client,
                              EnclaveInstance* enclave) {
  // Check flags
  CHECK_FLAGS(FLAGS_policy, "Empty policy file name");

  // Prepare the remotecall request
  kubetee::TaRemoteCallRequest req;
  kubetee::TaRemoteCallResponse res;
  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, req.mutable_auth_report()));
  req.set_function_name("TaDestorySecret");

  // Parse the secret policies from yaml file
  kubetee::SecretsParseResult result;
  aecs::client::SecretPolicyParser policy_parser(FLAGS_policy);
  TEE_CHECK_RETURN(policy_parser.Parse(&result));
  TeeErrorCode last_err = TEE_SUCCESS;
  for (int i = 0; i < result.secrets_size(); i++) {
    kubetee::TaCreateSecretRequest req_create;
    kubetee::TaCreateSecretResponse res_create;

    std::string secret_name = result.secrets()[i].spec().secret_name();
    TEE_LOG_INFO("Create the secret[%d]: %s", i, secret_name.c_str());
    req_create.mutable_secret()->CopyFrom(result.secrets()[i]);
    req_create.mutable_secret()->mutable_spec()->mutable_policy()->Clear();
    req_create.set_nonce(kTestNonce);
    if (!req_create.mutable_secret()->data().empty()) {
      // Because the request string only has integrity protection
      // Import data will result in data leakage
      TEE_LOG_ERROR("Cannot import TA bound secret: %s", secret_name.c_str());
      return AECS_ERROR_SECRET_CREATE_DATA_NOT_SUPPORT;
    }

    // Prepare signature in TEE side
    kubetee::UnifiedFunctionGenericRequest req_sig;
    kubetee::UnifiedFunctionGenericResponse res_sig;
    req_sig.clear_argv();
    res_sig.clear_result();
    PB2JSON(req_create, req_sig.add_argv());
    TEE_CHECK_RETURN(enclave->TeeRun("TeeIdentitySign", req_sig, &res_sig));

    // Call TA remotecall function
    req.set_req_json(req_sig.argv(0));
    req.set_signature_b64(res_sig.result(0));
    TEE_CHECK_RETURN(aecs_client->TaRemoteCall(req, &res));
  }

  return TEE_SUCCESS;
}

TeeErrorCode DoTaDestroySecret(AecsClient* aecs_client,
                               EnclaveInstance* enclave) {
  // Check flags
  CHECK_FLAGS(FLAGS_secret, "Empty secret name");

  // Prepare TaGetSecretRequest
  kubetee::TaDestroySecretRequest req_destroy;
  kubetee::TaDestroySecretResponse res_destroy;
  req_destroy.set_secret_name(FLAGS_secret);
  req_destroy.set_nonce(kTestNonce);

  // Prepare signature in TEE side
  kubetee::UnifiedFunctionGenericRequest req_sig;
  kubetee::UnifiedFunctionGenericResponse res_sig;
  PB2JSON(req_destroy, req_sig.add_argv());
  TEE_CHECK_RETURN(enclave->TeeRun("TeeIdentitySign", req_sig, &res_sig));

  // Prepare the remotecall request
  kubetee::TaRemoteCallRequest req;
  kubetee::TaRemoteCallResponse res;
  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, req.mutable_auth_report()));
  req.set_function_name("TaDestorySecret");
  req.set_req_json(req_sig.argv(0));
  req.set_signature_b64(res_sig.result(0));
  TEE_CHECK_RETURN(aecs_client->TaRemoteCall(req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode DoTaGetSecret(AecsClient* aecs_client, EnclaveInstance* enclave) {
  // Check flags
  CHECK_FLAGS(FLAGS_service, "Empty service name");
  CHECK_FLAGS(FLAGS_secret, "Empty secret name");

  // Prepare TaGetSecretRequest
  kubetee::TaGetSecretRequest req_get;
  kubetee::TaGetSecretResponse res_get;
  req_get.set_service_name(FLAGS_service);
  req_get.set_secret_name(FLAGS_secret);
  // FIXME: use hardcode nonce for test only, and also used trusted code
  // because we used the retured res as the req for TeeImportSecret,
  // there is no field to pass the nonce to trusted code
  // we don't want to add another proto file to do this.
  req_get.set_nonce("aecs_client");

  // Prepare signature in TEE side
  kubetee::UnifiedFunctionGenericRequest req_sig;
  kubetee::UnifiedFunctionGenericResponse res_sig;
  PB2JSON(req_get, req_sig.add_argv());
  TEE_CHECK_RETURN(enclave->TeeRun("TeeIdentitySign", req_sig, &res_sig));

  // Prepare the remotecall request
  kubetee::TaRemoteCallRequest req;
  kubetee::TaRemoteCallResponse res;
  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, req.mutable_auth_report()));
  req.set_function_name("TaGetSecret");
  req.set_req_json(req_sig.argv(0));
  req.set_signature_b64(res_sig.result(0));
  TEE_CHECK_RETURN(aecs_client->TaRemoteCall(req, &res));

  kubetee::UnifiedFunctionGenericResponse result;
  TEE_CHECK_RETURN(enclave->TeeRun("TeeImportSecret", res, &result));

  return TEE_SUCCESS;
}

// Main start
int main(int argc, char** argv) {
  // Initialize the gflags
  gflags::SetVersionString(kVersion);
  gflags::SetUsageMessage(kUsage);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Check the flags
  CHECK_FLAGS(FLAGS_action, "Please choose a action");

  // Create and initialize the enclave
  std::string enclave_file = ENCLAVE_FILENAME;
  std::string enclave_name = "EnclaveService";
  if (!FLAGS_enclave.empty()) {
    enclave_file.assign(FLAGS_enclave);
  }
  EnclaveInstance* enclave =
      EnclavesManager::GetInstance().CreateEnclave(enclave_name, enclave_file);
  if (!enclave) {
    printf("Fail to creates enclave %s", enclave_name.c_str());
    return AECS_ERROR_ENCLAVE_CREATE_FAILED;
  }

  // Do real things for the specified sub command
  aecs::untrusted::AecsClient aecs_client;
  if (FLAGS_action == "create") {
    TEE_CHECK_RETURN(DoTaCreateSecret(&aecs_client, enclave));
  } else if (FLAGS_action == "destroy") {
    TEE_CHECK_RETURN(DoTaDestroySecret(&aecs_client, enclave));
  } else if (FLAGS_action == "get") {
    TEE_CHECK_RETURN(DoTaGetSecret(&aecs_client, enclave));
  } else {
    TEE_LOG_ERROR("Invalid action: %s", FLAGS_action.c_str());
    return AECS_ERROR_PARAMETER_INVALID_ACTION;
  }

  return TEE_SUCCESS;
}
