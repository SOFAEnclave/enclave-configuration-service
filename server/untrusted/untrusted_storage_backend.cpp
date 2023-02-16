#include <dlfcn.h>  // dlopen

#include <string>

#include "aecs/error.h"
#include "untrusted/untrusted_aecs_config.h"
#include "untrusted/untrusted_storage_backend.h"

typedef TeeErrorCode (*StorageCreate)(const kubetee::StorageCreateRequest& req,
                                      kubetee::StorageCreateResponse* res);
typedef TeeErrorCode (*StorageDelete)(const kubetee::StorageDeleteRequest& req,
                                      kubetee::StorageDeleteResponse* res);
typedef TeeErrorCode (*StorageGetValue)(
    const kubetee::StorageGetValueRequest& req,
    kubetee::StorageGetValueResponse* res);
typedef TeeErrorCode (*StorageListAll)(
    const kubetee::StorageListAllRequest& req,
    kubetee::StorageListAllResponse* res);
typedef TeeErrorCode (*StorageCheckExist)(
    const kubetee::StorageCheckExistRequest& req,
    kubetee::StorageCheckExistResponse* res);

namespace aecs {
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

TeeErrorCode AecsStorageBackend::Create(
    const kubetee::StorageCreateRequest& req,
    kubetee::StorageCreateResponse* res) {
  TEE_LOG_DEBUG("Storage created: %s", req.name().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return AECS_ERROR_STORAGE_INVALID_LIB_OPENED;
  }

  StorageCreate pfunc_create =
      (StorageCreate)dlsym(dlopen_lib_, "StorageCreate");
  if (!pfunc_create) {
    TEE_LOG_ERROR("Can not find StorageCreate function: %s", dlerror());
    return AECS_ERROR_STORAGE_NO_FUNCTION_CREATE;
  }

  TEE_CHECK_RETURN((*pfunc_create)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::Delete(
    const kubetee::StorageDeleteRequest& req,
    kubetee::StorageDeleteResponse* res) {
  TEE_LOG_DEBUG("Storage delete prefix: %s", req.prefix().c_str());
  TEE_LOG_DEBUG("Storage delete name: %s", req.name().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return AECS_ERROR_STORAGE_INVALID_LIB_OPENED;
  }

  StorageDelete pfunc_delete =
      (StorageDelete)dlsym(dlopen_lib_, "StorageDelete");
  if (!pfunc_delete) {
    TEE_LOG_ERROR("Can not find StorageDelete function: %s", dlerror());
    return AECS_ERROR_STORAGE_NO_FUNCTION_DELETE;
  }

  TEE_CHECK_RETURN((*pfunc_delete)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::GetValue(
    const kubetee::StorageGetValueRequest& req,
    kubetee::StorageGetValueResponse* res) {
  TEE_LOG_DEBUG("Storage Get: %s", req.name().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return AECS_ERROR_STORAGE_INVALID_LIB_OPENED;
  }

  StorageGetValue pfunc_get =
      (StorageGetValue)dlsym(dlopen_lib_, "StorageGetValue");
  if (!pfunc_get) {
    TEE_LOG_ERROR("Can not find StorageGetValue function: %s", dlerror());
    return AECS_ERROR_STORAGE_NO_FUNCTION_GETVALUE;
  }

  TEE_CHECK_RETURN((*pfunc_get)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::ListAll(
    const kubetee::StorageListAllRequest& req,
    kubetee::StorageListAllResponse* res) {
  TEE_LOG_DEBUG("Storage list: %s", req.prefix().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return AECS_ERROR_STORAGE_INVALID_LIB_OPENED;
  }

  StorageListAll pfunc_list =
      (StorageListAll)dlsym(dlopen_lib_, "StorageListAll");
  if (!pfunc_list) {
    TEE_LOG_ERROR("Can not find StorageListAll function: %s", dlerror());
    return AECS_ERROR_STORAGE_NO_FUNCTION_LISTALL;
  }

  TEE_CHECK_RETURN((*pfunc_list)(req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsStorageBackend::CheckExist(
    const kubetee::StorageCheckExistRequest& req,
    kubetee::StorageCheckExistResponse* res) {
  TEE_LOG_DEBUG("Storage CheckExist: %s", req.name().c_str());
  if (!dlopen_lib_) {
    TEE_LOG_ERROR_TRACE();
    return AECS_ERROR_STORAGE_INVALID_LIB_OPENED;
  }

  StorageCheckExist pfunc_chk =
      (StorageCheckExist)dlsym(dlopen_lib_, "StorageCheckExist");
  if (!pfunc_chk) {
    TEE_LOG_ERROR("Can not find StorageCheckExist function: %s", dlerror());
    return AECS_ERROR_STORAGE_NO_FUNCTION_CHECKEXIST;
  }

  TEE_CHECK_RETURN((*pfunc_chk)(req, res));
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace aecs
