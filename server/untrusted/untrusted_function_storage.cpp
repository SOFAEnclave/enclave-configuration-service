#include <string>

#include "tee/common/error.h"
#include "tee/common/type.h"

#include "tee/untrusted/enclave/untrusted_enclave.h"
#include "tee/untrusted/untrusted_pbcall.h"

#include "untrusted/untrusted_storage_backend.h"

#include "./aecs.pb.h"
#include "./enclave_u.h"

using tee::untrusted::AecsStorageBackend;

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode ReeStorageCreate(const std::string& req_str,
                              std::string* res_str) {
  tee::StorageCreateRequest req;
  tee::StorageCreateResponse res;

  PB_PARSE(req, req_str);
  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().Create(req, &res));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageDelete(const std::string& req_str,
                              std::string* res_str) {
  tee::StorageDeleteRequest req;
  tee::StorageDeleteResponse res;

  PB_PARSE(req, req_str);
  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().Delete(req, &res));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageGetValue(const std::string& req_str,
                                std::string* res_str) {
  tee::StorageGetValueRequest req;
  tee::StorageGetValueResponse res;

  PB_PARSE(req, req_str);
  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().GetValue(req, &res));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageListAll(const std::string& req_str,
                               std::string* res_str) {
  tee::StorageListAllRequest req;
  tee::StorageListAllResponse res;

  PB_PARSE(req, req_str);
  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().ListAll(req, &res));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageCheckExist(const std::string& req_str,
                                  std::string* res_str) {
  tee::StorageCheckExistRequest req;
  tee::StorageCheckExistResponse res;

  PB_PARSE(req, req_str);
  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().CheckExist(req, &res));

  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode RegisterUntrustedPbFunctionsEx() {
  ELOG_DEBUG("Register application untrusted functions");
  ADD_UNTRUSTED_PBCALL_FUNCTION(ReeStorageCreate);
  ADD_UNTRUSTED_PBCALL_FUNCTION(ReeStorageDelete);
  ADD_UNTRUSTED_PBCALL_FUNCTION(ReeStorageGetValue);
  ADD_UNTRUSTED_PBCALL_FUNCTION(ReeStorageListAll);
  ADD_UNTRUSTED_PBCALL_FUNCTION(ReeStorageCheckExist);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
