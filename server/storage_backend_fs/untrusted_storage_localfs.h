#ifndef SERVER_STORAGE_BACKEND_FS_UNTRUSTED_STORAGE_LOCALFS_H_
#define SERVER_STORAGE_BACKEND_FS_UNTRUSTED_STORAGE_LOCALFS_H_

#include <string>
#include <vector>

#include "tee/common/type.h"

#include "./aecs.pb.h"

namespace tee {
namespace untrusted {

class StorageLocalFs {
 public:
  StorageLocalFs();

  TeeErrorCode Create(const tee::StorageCreateRequest& req,
                      tee::StorageCreateResponse* res);
  TeeErrorCode Delete(const tee::StorageDeleteRequest& req,
                      tee::StorageDeleteResponse* res);
  TeeErrorCode GetValue(const tee::StorageGetValueRequest& req,
                        tee::StorageGetValueResponse* res);
  TeeErrorCode ListAll(const tee::StorageListAllRequest& req,
                       tee::StorageListAllResponse* res);
  TeeErrorCode CheckExist(const tee::StorageCheckExistRequest& req,
                          tee::StorageCheckExistResponse* res);
};

}  // namespace untrusted
}  // namespace tee

#endif  // SERVER_STORAGE_BACKEND_FS_UNTRUSTED_STORAGE_LOCALFS_H_
