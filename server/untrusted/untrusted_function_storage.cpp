#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "untrusted/untrusted_function_storage.h"
#include "untrusted/untrusted_storage_backend.h"

#include "./aecs.pb.h"
#include "./enclave_u.h"

using aecs::untrusted::AecsStorageBackend;

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode ReeStorageCreate(const std::string& req_str,
                              std::string* res_str) {
  kubetee::StorageCreateRequest req;
  kubetee::StorageCreateResponse res;
  JSON2PB(req_str, &req);

  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().Create(req, &res));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageDelete(const std::string& req_str,
                              std::string* res_str) {
  kubetee::StorageDeleteRequest req;
  kubetee::StorageDeleteResponse res;
  JSON2PB(req_str, &req);

  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().Delete(req, &res));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageGetValue(const std::string& req_str,
                                std::string* res_str) {
  kubetee::StorageGetValueRequest req;
  kubetee::StorageGetValueResponse res;
  JSON2PB(req_str, &req);

  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().GetValue(req, &res));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageListAll(const std::string& req_str,
                               std::string* res_str) {
  kubetee::StorageListAllRequest req;
  kubetee::StorageListAllResponse res;
  JSON2PB(req_str, &req);

  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().ListAll(req, &res));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode ReeStorageCheckExist(const std::string& req_str,
                                  std::string* res_str) {
  kubetee::StorageCheckExistRequest req;
  kubetee::StorageCheckExistResponse res;
  JSON2PB(req_str, &req);

  TEE_CHECK_RETURN(AecsStorageBackend::GetInstance().CheckExist(req, &res));

  PB2JSON(res, res_str);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
