#include <iostream>
#include <string>

#include "./sgx_eid.h"    // sgx_enclave_id_t
#include "./sgx_error.h"  // sgx_status_t
#include "./sgx_urts.h"

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"
#include "aecs/untrusted_enclave.h"

#include "untrusted/untrusted_aecs_config.h"
#include "untrusted/untrusted_aecs_server.h"

#include "./enclave_u.h"

int SGX_CDECL main(void) {
  // Create and initialize the enclave
  std::string enclave_file = AECS_CONF_STR(kAecsConfServerEnclave);
  EnclaveInstance* enclave = EnclavesManager::GetInstance().CreateEnclave(
      kAecsServerName, enclave_file);
  if (!enclave) {
    TEE_LOG_ERROR("Fail to creates enclave %s", kAecsServerName);
    return AECS_ERROR_ENCLAVE_CREATE_FAILED;
  }

  // Import the AECS administrator public key from configuration file
  // The configuration is signed in release mode, it is more secure
  // than reading it from another local file.
  kubetee::AecsAdminInitializeRequest req;
  kubetee::AecsAdminInitializeResponse res;
  kubetee::common::DataBytes public_key(AECS_CONF_STR(kAecsConfAdminPubKey));
  std::string password_hash = AECS_CONF_STR(kAecsConfAdminPasswordHash);
  kubetee::AdminAuth* aecs_admin_auth = req.mutable_admin();
  aecs_admin_auth->set_public_key(public_key.FromBase64().GetStr());
  aecs_admin_auth->set_password_hash(password_hash);
  if (aecs_admin_auth->public_key().empty()) {
    TEE_LOG_ERROR("Fail to convert the base64 public key");
    return AECS_ERROR_ADMIN_INVALID_BASE64_PUBLIC_KEY;
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
