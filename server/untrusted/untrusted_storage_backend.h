#ifndef SERVER_UNTRUSTED_UNTRUSTED_STORAGE_BACKEND_H_
#define SERVER_UNTRUSTED_UNTRUSTED_STORAGE_BACKEND_H_

#include <string>
#include <vector>

#include "tee/common/type.h"

#include "./aecs.pb.h"

namespace tee {
namespace untrusted {

class AecsStorageBackend {
 public:
  // Single instance for loading the storage back-end so file
  static AecsStorageBackend& GetInstance() {
    static AecsStorageBackend instance_;
    return instance_;
  }

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

 private:
  // Hide construction functions
  AecsStorageBackend();
  ~AecsStorageBackend();
  AecsStorageBackend(const AecsStorageBackend&);
  void operator=(AecsStorageBackend const&);

  void* dlopen_lib_;
};

}  // namespace untrusted
}  // namespace tee

#endif  // SERVER_UNTRUSTED_UNTRUSTED_STORAGE_BACKEND_H_
