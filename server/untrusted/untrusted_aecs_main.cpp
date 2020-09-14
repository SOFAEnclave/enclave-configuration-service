#include <iostream>
#include <string>

#include "./sgx_eid.h"    // sgx_enclave_id_t
#include "./sgx_error.h"  // sgx_status_t
#include "./sgx_urts.h"

#include "tee/common/bytes.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/untrusted/enclave/untrusted_enclave.h"

#include "untrusted/untrusted_aecs_config.h"
#include "untrusted/untrusted_aecs_server.h"

#include "./enclave_u.h"

#define ENCLAVE_FILENAME "aecs_enclave.signed.so"

int SGX_CDECL main(void) {
  // Create and initialize the enclave
  std::string enclave_name = "AecsServer";
  EnclaveInstance* enclave = EnclavesManager::GetInstance().CreateEnclave(
      enclave_name, ENCLAVE_FILENAME);
  if (!enclave) {
    printf("Fail to creates enclave %s", enclave_name.c_str());
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  // Import the AECS administrator public key from configuration file
  // The configuration is signed in release mode, it is more secure
  // than reading it from another local file.
  tee::AecsAdminInitializeRequest req;
  tee::AecsAdminInitializeResponse res;
  tee::common::DataBytes public_key(AECS_CONF_STR(kAecsConfAdminPubKey));
  tee::AdminSecrets* admin = req.mutable_admin();
  admin->set_public_key(public_key.FromBase64().GetStr());
  if (admin->public_key().empty()) {
    TEE_LOG_ERROR("Fail to convert the base64 public key");
    return TEE_ERROR_UNEXPECTED;
  }
  TEE_CHECK_RETURN(enclave->TeeRun("TeeInitializeAecsAdmin", req, &res));

  // Initialize the AECS service (sync identity, update local report)
  aecs::untrusted::AecsServer aecs_server;
  TeeErrorCode ret = aecs_server.InitServer(enclave);
  if (ret != TEE_SUCCESS) {
    return ret;
  }
  TEE_LOG_INFO("Initialize AECS service successfully");

  // Run as AECS server and wait for the sync requests
  return aecs_server.RunServer();
}
