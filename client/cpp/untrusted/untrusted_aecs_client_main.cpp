#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "untrusted/untrusted_aecs_client.h"

#include "aecs/error.h"
#include "aecs/untrusted_enclave.h"

#include "gflags/gflags.h"

#include "./aecs.pb.h"

#define ENCLAVE_FILENAME "/usr/lib64/aecs_client_test_enclave.signed.so"

static const char kVersion[] = "v1";
static const char kUsage[] = "aecs_client_test_service [option-flags ...]";

// Define the command line options
DEFINE_string(service, "", "service name");
DEFINE_string(secret, "", "secret name");

static TeeErrorCode AddEnclaveSeriveAuth(
    EnclaveInstance* enclave, kubetee::UnifiedAttestationAuthReport* auth) {
  TEE_CHECK_RETURN(enclave->CreateRaReport());
  auth->CopyFrom(enclave->GetLocalAuthReport());
  return TEE_SUCCESS;
}

int main(int argc, char** argv) {
  // Initialize the gflags
  gflags::SetVersionString(kVersion);
  gflags::SetUsageMessage(kUsage);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Check the flags
  if (FLAGS_service.empty()) {
    TEE_LOG_ERROR("Please specify the service name");
    return AECS_ERROR_PARAMETER_FLAGS_EMPTT;
  }
  if (FLAGS_secret.empty()) {
    TEE_LOG_ERROR("Please specify the secret name");
    return AECS_ERROR_PARAMETER_FLAGS_EMPTT;
  }

  // Create and initialize the enclave
  std::string enclave_name = "EnclaveService";
  EnclaveInstance* enclave = EnclavesManager::GetInstance().CreateEnclave(
      enclave_name, ENCLAVE_FILENAME);
  if (!enclave) {
    printf("Fail to creates enclave %s", enclave_name.c_str());
    return AECS_ERROR_ENCLAVE_CREATE_FAILED;
  }

  aecs::untrusted::AecsClient aecs_client;
  kubetee::GetEnclaveSecretRequest req;
  kubetee::GetEnclaveSecretResponse res;
  kubetee::UnifiedAttestationAuthReport* auth = req.mutable_auth_ra_report();
  TEE_CHECK_RETURN(AddEnclaveSeriveAuth(enclave, auth));
  req.set_service_name(FLAGS_service);
  req.set_secret_name(FLAGS_secret);
  TEE_CHECK_RETURN(aecs_client.GetEnclaveSecret(req, &res));

  kubetee::UnifiedFunctionGenericResponse result;
  TEE_CHECK_RETURN(enclave->TeeRun("TeeImportSecret", res, &result));

  return TEE_SUCCESS;
}
