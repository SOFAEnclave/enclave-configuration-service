#ifndef SERVER_STORAGE_BACKEND_FS_UNTRUSTED_STORAGE_LOCALFS_H_
#define SERVER_STORAGE_BACKEND_FS_UNTRUSTED_STORAGE_LOCALFS_H_

#include <string>
#include <vector>

#include "unified_attestation/ua_untrusted.h"

#include "./aecs.pb.h"

namespace kubetee {
namespace untrusted {

class StorageLocalFs {
 public:
  StorageLocalFs();

  TeeErrorCode Create(const kubetee::StorageCreateRequest& req,
                      kubetee::StorageCreateResponse* res);
  TeeErrorCode Delete(const kubetee::StorageDeleteRequest& req,
                      kubetee::StorageDeleteResponse* res);
  TeeErrorCode GetValue(const kubetee::StorageGetValueRequest& req,
                        kubetee::StorageGetValueResponse* res);
  TeeErrorCode ListAll(const kubetee::StorageListAllRequest& req,
                       kubetee::StorageListAllResponse* res);
  TeeErrorCode CheckExist(const kubetee::StorageCheckExistRequest& req,
                          kubetee::StorageCheckExistResponse* res);

 private:
  static std::string DirName(const std::string& path);
  static std::string BaseName(const std::string& path);
  static TeeErrorCode MakeDir(const std::string& path);
};

}  // namespace untrusted
}  // namespace kubetee

#endif  // SERVER_STORAGE_BACKEND_FS_UNTRUSTED_STORAGE_LOCALFS_H_
