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
    "\ttacreate      Creates trusted application bound secrets by yaml conf\n"
    "\ttadestroy     Destroy a trusted application bound secret by name\n"
    "\ttaget         Get secret created by trusted application\n"
    "\tget           Get secret created by serivceadmin or trusted "
    "application\n";

// Define the command line options
DEFINE_string(action, "", "action name [create/destroy/get]");
DEFINE_string(service, "", "service name");
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

TeeErrorCode DoCreateTaSecret(AecsClient* aecs_client,
                              EnclaveInstance* enclave) {
  kubetee::CreateTaSecretRequest req;
  kubetee::CreateTaSecretResponse res;

  // Check flags
  CHECK_FLAGS(FLAGS_policy, "Empty policy file name");

  // Prepare trusted application auth report
  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, req.mutable_auth_ra_report()));

  // Parse the secret policies from yaml file
  kubetee::SecretsParseResult result;
  aecs::client::SecretPolicyParser policy_parser(FLAGS_policy);
  TEE_CHECK_RETURN(policy_parser.Parse(&result));
  for (int i = 0; i < result.secrets_size(); i++) {
    std::string secret_name = result.secrets()[i].spec().secret_name();
    TEE_LOG_INFO("Create the secret[%d]: %s", i, secret_name.c_str());
    req.mutable_secret()->CopyFrom(result.secrets()[i]);
    req.mutable_secret()->mutable_spec()->mutable_policy()->Clear();
    if (aecs_client->CreateTaSecret(req, &res)) {
      TEE_LOG_ERROR("Fail to create secret: %s", secret_name.c_str());
    }
  }
  return TEE_SUCCESS;
}

TeeErrorCode DoDestroyTaSecret(AecsClient* aecs_client,
                               EnclaveInstance* enclave) {
  kubetee::DestroyTaSecretRequest req;
  kubetee::DestroyTaSecretResponse res;

  // Check flags
  CHECK_FLAGS(FLAGS_secret, "Empty secret name");

  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, req.mutable_auth_ra_report()));
  req.set_secret_name(FLAGS_secret);
  TEE_CHECK_RETURN(aecs_client->DestroyTaSecret(req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode DoGetEnclaveSecret(AecsClient* aecs_client,
                                EnclaveInstance* enclave) {
  kubetee::GetEnclaveSecretRequest req;
  kubetee::GetEnclaveSecretResponse res;

  // Check flags
  CHECK_FLAGS(FLAGS_service, "Empty service name");
  CHECK_FLAGS(FLAGS_secret, "Empty secret name");

  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, req.mutable_auth_ra_report()));
  req.set_service_name(FLAGS_service);
  req.set_secret_name(FLAGS_secret);
  // FIXME: use hardcode nonce for test only, and also used trusted code
  // because we used the retured res as the req for TeeImportSecret,
  // there is no field to pass the nonce to trusted code
  // we don't want to add another proto file to do this.
  req.set_nonce("aecs_client");
  TEE_CHECK_RETURN(aecs_client->GetEnclaveSecret(req, &res));

  kubetee::UnifiedFunctionGenericResponse result;
  TEE_CHECK_RETURN(enclave->TeeRun("TeeImportSecret", res, &result));

  return TEE_SUCCESS;
}

TeeErrorCode DoGetTaSecret(AecsClient* aecs_client, EnclaveInstance* enclave) {
  kubetee::GetTaSecretRequest req;
  kubetee::GetTaSecretResponse res;

  // Check flags
  CHECK_FLAGS(FLAGS_secret, "Empty secret name");

  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, req.mutable_auth_ra_report()));
  req.set_secret_name(FLAGS_secret);
  // FIXME: use hardcode nonce for test only, and also used trusted code
  // because we used the retured res as the req for TeeImportSecret,
  // there is no field to pass the nonce to trusted code
  // we don't want to add another proto file to do this.
  req.set_nonce("aecs_client");
  TEE_CHECK_RETURN(aecs_client->GetTaSecret(req, &res));

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
  if (FLAGS_action == "tacreate") {
    TEE_CHECK_RETURN(DoCreateTaSecret(&aecs_client, enclave));
  } else if (FLAGS_action == "tadestroy") {
    TEE_CHECK_RETURN(DoDestroyTaSecret(&aecs_client, enclave));
  } else if (FLAGS_action == "taget") {
    TEE_CHECK_RETURN(DoGetTaSecret(&aecs_client, enclave));
  } else if (FLAGS_action == "get") {
    TEE_CHECK_RETURN(DoGetEnclaveSecret(&aecs_client, enclave));
  } else {
    TEE_LOG_ERROR("Invalid action: %s", FLAGS_action.c_str());
    return AECS_ERROR_PARAMETER_INVALID_ACTION;
  }

  return TEE_SUCCESS;
}
