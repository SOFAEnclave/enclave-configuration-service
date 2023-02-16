#ifndef SERVER_UNTRUSTED_UNTRUSTED_STORAGE_BACKEND_H_
#define SERVER_UNTRUSTED_UNTRUSTED_STORAGE_BACKEND_H_

#include <string>
#include <vector>

#include "unified_attestation/ua_untrusted.h"

#include "./aecs.pb.h"

namespace aecs {
namespace untrusted {

class AecsStorageBackend {
 public:
  // Single instance for loading the storage back-end so file
  static AecsStorageBackend& GetInstance() {
    static AecsStorageBackend instance_;
    return instance_;
  }

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
  // Hide construction functions
  AecsStorageBackend();
  ~AecsStorageBackend();
  AecsStorageBackend(const AecsStorageBackend&);
  void operator=(AecsStorageBackend const&);

  void* dlopen_lib_;
};

}  // namespace untrusted
}  // namespace aecs

#endif  // SERVER_UNTRUSTED_UNTRUSTED_STORAGE_BACKEND_H_
