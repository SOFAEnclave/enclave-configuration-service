#include <dirent.h>  // opendir/readdir

#include <cstdlib>  // system()
#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"

#include "server/storage_backend_fs/untrusted_storage_localfs.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode StorageCreate(const kubetee::StorageCreateRequest& req,
                           kubetee::StorageCreateResponse* res) {
  TEE_LOG_DEBUG("StorageCreate: %s", req.name().c_str());

  kubetee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.Create(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageDelete(const kubetee::StorageDeleteRequest& req,
                           kubetee::StorageDeleteResponse* res) {
  TEE_LOG_DEBUG("StorageDelete: %s", req.prefix().c_str());

  kubetee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.Delete(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageGetValue(const kubetee::StorageGetValueRequest& req,
                             kubetee::StorageGetValueResponse* res) {
  TEE_LOG_DEBUG("StorageGet: %s", req.name().c_str());

  kubetee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.GetValue(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageListAll(const kubetee::StorageListAllRequest& req,
                            kubetee::StorageListAllResponse* res) {
  TEE_LOG_DEBUG("StorageListAll: %s", req.prefix().c_str());

  kubetee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.ListAll(req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageCheckExist(const kubetee::StorageCheckExistRequest& req,
                               kubetee::StorageCheckExistResponse* res) {
  TEE_LOG_DEBUG("StorageCheckExist: %s", req.name().c_str());

  kubetee::untrusted::StorageLocalFs storage;
  TEE_CHECK_RETURN(storage.CheckExist(req, res));

  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace untrusted {

using kubetee::utils::FsFileExists;
using kubetee::utils::FsReadString;
using kubetee::utils::FsWriteString;

// By default, application is running in  build/out directory.
// This default path is in the code repository top directory.
// TODO(junxian) Get it from configuration file, e.g. "file:://xxx"
static constexpr char kLocalFsPrefixPath[] = "./storage/";

std::string StorageLocalFs::DirName(const std::string& path) {
  // Get the dirname of path
  std::size_t found = path.find_last_of("/\\");
  if (found == std::string::npos) {
    return path;
  } else {
    return path.substr(0, found);
  }
}

std::string StorageLocalFs::BaseName(const std::string& path) {
  // Get the dirname of path
  std::size_t found = path.find_last_of("/");
  if (found == std::string::npos) {
    return path;
  } else {
    return path.substr(found + 1, path.size());
  }
}

TeeErrorCode StorageLocalFs::MakeDir(const std::string& path) {
  // Run the "mkdir -p $dirname" command
  std::string command = "mkdir -p ";
  command.append(StorageLocalFs::DirName(path));
  if (system(command.c_str()) != 0) {
    TEE_LOG_ERROR("Fail to \"%s\"", command.c_str());
    return AECS_ERROR_STORAGE_FS_MKDIR;
  }
  return TEE_SUCCESS;
}

StorageLocalFs::StorageLocalFs() {
  // Create the top directory
  if (MakeDir(kLocalFsPrefixPath) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to create directory: %s", kLocalFsPrefixPath);
  }
}

TeeErrorCode StorageLocalFs::Create(const kubetee::StorageCreateRequest& req,
                                    kubetee::StorageCreateResponse* res) {
  std::string filename = kLocalFsPrefixPath + req.name();

  // Try to create the directory if parent path doesn't exist
  TEE_CHECK_RETURN(MakeDir(filename));

  if (!req.force()) {
    if (FsFileExists(filename)) {
      TEE_LOG_ERROR("Key name has already existed: %s", filename.c_str());
      return AECS_ERROR_STORAGE_FS_CREATE_NAME_EXISTED;
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

TeeErrorCode StorageLocalFs::Delete(const kubetee::StorageDeleteRequest& req,
                                    kubetee::StorageDeleteResponse* res) {
  std::string filename = kLocalFsPrefixPath;
  std::string command = "rm -rf ";
  if (!req.name().empty()) {
    filename.append(req.name());
    command.append(filename);
  } else if (!req.prefix().empty()) {
    filename.append(req.prefix());
    std::string basename = BaseName(filename);
    if (basename.empty()) {
      command.append(DirName(filename));
    } else {
      command.append(filename + "*");
    }
  } else {
    TEE_LOG_ERROR("Both prefix and name are empty when delete objects");
    return AECS_ERROR_STORAGE_FS_DELETE_EMPTY_PREFIX;
  }

  TEE_LOG_DEBUG("Storage Delete: %s*", command.c_str());
  if (system(command.c_str()) != 0) {
    TEE_LOG_ERROR("Fail to delete file: %s*", filename.c_str());
    return AECS_ERROR_STORAGE_FS_DELETE_FAILED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode StorageLocalFs::GetValue(
    const kubetee::StorageGetValueRequest& req,
    kubetee::StorageGetValueResponse* res) {
  std::string filename = kLocalFsPrefixPath + req.name();
  if (!FsFileExists(filename)) {
    TEE_LOG_ERROR("Key name doesn't exist: %s", filename.c_str());
    return AECS_ERROR_STORAGE_FS_GET_NAME_NOT_EXISTED;
  }
  TeeErrorCode ret = FsReadString(filename, res->mutable_value());
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR_TRACE();
    return ret;
  }
  TEE_LOG_DEBUG("Storage Get: %s", filename.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode StorageLocalFs::ListAll(const kubetee::StorageListAllRequest& req,
                                     kubetee::StorageListAllResponse* res) {
  std::string prefix = kLocalFsPrefixPath + req.prefix();
  DIR* pdir = opendir(DirName(prefix).c_str());
  if (!pdir) {
    TEE_LOG_WARN("Fail to open local fs storage directory");
    // return success if file to open directory
    // return AECS_ERROR_STORAGE_FS_LIST_OPEN_DIR_FAILED;
    return TEE_SUCCESS;
  }

  // Read all the files in the storage dir
  struct dirent* pdirent = NULL;
  std::string basename = BaseName(prefix);
  TEE_LOG_DEBUG("ListAll: basename=\"%s\"", basename.c_str());
  while ((pdirent = readdir(pdir)) != NULL) {
    std::string dname = pdirent->d_name;
    // Exclude the "." and ".."
    if ((dname == ".") || (dname == "..")) {
      continue;
    }
    TEE_LOG_DEBUG("ListAll: %s", dname.c_str());
    if (basename.empty()) {
      res->add_names(dname);
    } else if (dname.find(basename) != std::string::npos) {
      res->add_names(dname);
    }
  }
  TEE_LOG_DEBUG("Storage List All, total: %ld", res->names_size());
  return TEE_SUCCESS;
}

TeeErrorCode StorageLocalFs::CheckExist(
    const kubetee::StorageCheckExistRequest& req,
    kubetee::StorageCheckExistResponse* res) {
  std::string filename = kLocalFsPrefixPath + req.name();
  res->set_exist(FsFileExists(filename) ? true : false);
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace kubetee
