#include <dlfcn.h>  // dlopen

#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/untrusted/untrusted_config.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "untrusted/untrusted_aecs_config.h"
#include "untrusted/untrusted_storage_backend.h"

typedef TeeErrorCode (*StorageCreate)(const tee::StorageCreateRequest& req,
                                      tee::StorageCreateResponse* res);
typedef TeeErrorCode (*StorageDelete)(const tee::StorageDeleteRequest& req,
                                      tee::StorageDeleteResponse* res);
typedef TeeErrorCode (*StorageGetValue)(const tee::StorageGetValueRequest& req,
                                        tee::StorageGetValueResponse* res);
typedef TeeErrorCode (*StorageListAll)(const tee::StorageListAllRequest& req,
                                       tee::StorageListAllResponse* res);
typedef TeeErrorCode (*StorageCheckExist)(
    const tee::StorageCheckExistRequest& req,
    tee::StorageCheckExistResponse* res);

namespace tee {
namespace untrusted {

AecsStorageBackend::AecsStorageBackend() {
  std::string libpath = AECS_CONF_STR(kAecsConfBackendLib);
  dlopen_lib_ = dlopen(libpath.c_str(), RTLD_LAZY);
  if (!dlopen_lib_) {
    TEE_LOG_ERROR("Fail to open library: %s", libpath.c_str());
    TEE_LOG_ERROR("Error message: %s", dlerror());
  }
}

AecsStorageBackend::~AecsStorageBackend() {
  TEE_LOG_ERROR("Close storage backend library");
  if (dlopen_lib_) {
    dlclose(dlopen_lib_);
  }
}

TeeErrorCode AecsStorageBackend::Create(const tee::StorageCreateRequest& req,
                                        tee::StorageCreateResponse* res) {
  TEE_LOG_DEBUG("Storage created: %s", req.name().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return TEE_ERROR_UNEXPECTED;
  }

  StorageCreate pfunc_create =
      (StorageCreate)dlsym(dlopen_lib_, "StorageCreate");
  if (!pfunc_create) {
    TEE_LOG_ERROR("Can not find StorageCreate function: %s", dlerror());
    return TEE_ERROR_UNEXPECTED;
  }

  TEE_CHECK_RETURN((*pfunc_create)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::Delete(const tee::StorageDeleteRequest& req,
                                        tee::StorageDeleteResponse* res) {
  TEE_LOG_DEBUG("Storage delete: %s", req.pattern().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return TEE_ERROR_UNEXPECTED;
  }

  StorageDelete pfunc_delete =
      (StorageDelete)dlsym(dlopen_lib_, "StorageDelete");
  if (!pfunc_delete) {
    TEE_LOG_ERROR("Can not find StorageDelete function: %s", dlerror());
    return TEE_ERROR_UNEXPECTED;
  }

  TEE_CHECK_RETURN((*pfunc_delete)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::GetValue(
    const tee::StorageGetValueRequest& req, tee::StorageGetValueResponse* res) {
  TEE_LOG_DEBUG("Storage Get: %s", req.name().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return TEE_ERROR_UNEXPECTED;
  }

  StorageGetValue pfunc_get =
      (StorageGetValue)dlsym(dlopen_lib_, "StorageGetValue");
  if (!pfunc_get) {
    TEE_LOG_ERROR("Can not find StorageGetValue function: %s", dlerror());
    return TEE_ERROR_UNEXPECTED;
  }

  TEE_CHECK_RETURN((*pfunc_get)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::ListAll(const tee::StorageListAllRequest& req,
                                         tee::StorageListAllResponse* res) {
  TEE_LOG_DEBUG("Storage list: %s", req.pattern().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return TEE_ERROR_UNEXPECTED;
  }

  StorageListAll pfunc_list =
      (StorageListAll)dlsym(dlopen_lib_, "StorageListAll");
  if (!pfunc_list) {
    TEE_LOG_ERROR("Can not find StorageListAll function: %s", dlerror());
    return TEE_ERROR_UNEXPECTED;
  }

  TEE_CHECK_RETURN((*pfunc_list)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::CheckExist(
    const tee::StorageCheckExistRequest& req,
    tee::StorageCheckExistResponse* res) {
  TEE_LOG_DEBUG("Storage CheckExist: %s", req.name().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return TEE_ERROR_UNEXPECTED;
  }

  StorageCheckExist pfunc_chk =
      (StorageCheckExist)dlsym(dlopen_lib_, "StorageCheckExist");
  if (!pfunc_chk) {
    TEE_LOG_ERROR("Can not find StorageCheckExist function: %s", dlerror());
    return TEE_ERROR_UNEXPECTED;
  }

  TEE_CHECK_RETURN((*pfunc_chk)(req, res));
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace tee
