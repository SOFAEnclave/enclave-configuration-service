#include <dirent.h>  // opendir/readdir

#include <cstdlib>  // system()
#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "server/storage_backend_fs/untrusted_storage_localfs.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode StorageCreate(const tee::StorageCreateRequest& req,
                           tee::StorageCreateResponse* res) {
  TEE_LOG_DEBUG("StorageCreate: %s", req.name().c_str());

  tee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.Create(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageDelete(const tee::StorageDeleteRequest& req,
                           tee::StorageDeleteResponse* res) {
  TEE_LOG_DEBUG("StorageDelete: %s", req.prefix().c_str());

  tee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.Delete(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageGetValue(const tee::StorageGetValueRequest& req,
                             tee::StorageGetValueResponse* res) {
  TEE_LOG_DEBUG("StorageGet: %s", req.name().c_str());

  tee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.GetValue(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageListAll(const tee::StorageListAllRequest& req,
                            tee::StorageListAllResponse* res) {
  TEE_LOG_DEBUG("StorageListAll: %s", req.pattern().c_str());

  tee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.ListAll(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageCheckExist(const tee::StorageCheckExistRequest& req,
                               tee::StorageCheckExistResponse* res) {
  TEE_LOG_DEBUG("StorageCheckExist: %s", req.name().c_str());

  tee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.CheckExist(req, res));

  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif

namespace tee {
namespace untrusted {

// By default, application is running in  build/out directory.
// This default path is in the code repository top directory.
// TODO(junxian) Get it from configuration file, e.g. "file:://xxx"
static constexpr char kLocalFsPrefixPath[] = "./storage/";

StorageLocalFs::StorageLocalFs() {
  // Create the top directory
  std::string command = "mkdir -p ";
  command.append(kLocalFsPrefixPath);
  if (system(command.c_str()) != 0) {
    TEE_LOG_ERROR("Fail to create directory: %s", kLocalFsPrefixPath);
  }
}

TeeErrorCode StorageLocalFs::Create(const tee::StorageCreateRequest& req,
                                    tee::StorageCreateResponse* res) {
  std::string filename = kLocalFsPrefixPath + req.name();
  if (!req.has_force() || !req.force()) {
    if (FsFileExists(filename)) {
      TEE_LOG_ERROR("Key name has already existed: %s", filename.c_str());
      return TEE_ERROR_PARAMETERS;
    }
  } else {
    TEE_LOG_DEBUG("Update %s", filename.c_str());
  }

  TeeErrorCode ret = FsWriteString(filename, req.value());
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR_TRACE();
    return ret;
  }
  TEE_LOG_DEBUG("Storage created: %s", filename.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode StorageLocalFs::Delete(const tee::StorageDeleteRequest& req,
                                    tee::StorageDeleteResponse* res) {
  std::string filename = kLocalFsPrefixPath + req.prefix();
  std::string command = "rm " + filename + "*";
  if (system(command.c_str()) != 0) {
    TEE_LOG_ERROR("Fail to delete file: %s*", filename.c_str());
    return TEE_ERROR_UNEXPECTED;
  }
  TEE_LOG_DEBUG("Storage Delete: %s*", filename.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode StorageLocalFs::GetValue(const tee::StorageGetValueRequest& req,
                                      tee::StorageGetValueResponse* res) {
  std::string filename = kLocalFsPrefixPath + req.name();
  if (!FsFileExists(filename)) {
    TEE_LOG_ERROR("Key name doesn't exist: %s", filename.c_str());
    return TEE_ERROR_PARAMETERS;
  }
  TeeErrorCode ret = FsReadString(filename, res->mutable_value());
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR_TRACE();
    return ret;
  }
  TEE_LOG_DEBUG("Storage Get: %s", filename.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode StorageLocalFs::ListAll(const tee::StorageListAllRequest& req,
                                     tee::StorageListAllResponse* res) {
  DIR* pdir = opendir(kLocalFsPrefixPath);
  if (!pdir) {
    TEE_LOG_ERROR("Fail to open local fs storage directory");
    return TEE_ERROR_FILE_OPEN;
  }

  // Read all the files in the storage dir
  struct dirent* pdirent = NULL;
  while ((pdirent = readdir(pdir)) != NULL) {
    std::string dname = pdirent->d_name;
    // Exclude the "." and ".."
    if ((dname == ".") || (dname == "..")) {
      continue;
    }
    if (req.pattern().empty()) {
      res->add_names(dname);
    } else if (dname.find(req.pattern()) != std::string::npos) {
      res->add_names(dname);
    }
  }
  TEE_LOG_DEBUG("Storage List All, total: %ld", res->names_size());
  return TEE_SUCCESS;
}

TeeErrorCode StorageLocalFs::CheckExist(
    const tee::StorageCheckExistRequest& req,
    tee::StorageCheckExistResponse* res) {
  std::string filename = kLocalFsPrefixPath + req.name();
  res->set_exist(FsFileExists(filename) ? true : false);
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace tee
