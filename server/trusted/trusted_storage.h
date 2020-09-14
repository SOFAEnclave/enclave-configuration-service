#ifndef SERVER_TRUSTED_TRUSTED_STORAGE_H_
#define SERVER_TRUSTED_TRUSTED_STORAGE_H_

#include <string>

#include "tee/common/error.h"

#include "./aecs.pb.h"

namespace tee {
namespace trusted {

class StorageTrustedBridge {
 public:
  static StorageTrustedBridge& GetInstance() {
    static StorageTrustedBridge instance_;
    return instance_;
  }

  TeeErrorCode SetAuth(const tee::StorageAuth& auth);
  const tee::StorageAuth& GetAuth() {
    return auth_;
  }

  TeeErrorCode Create(const std::string& name,
                      const std::string& value,
                      const bool identity_encrypt = true);
  TeeErrorCode Delete(const std::string& pattern);
  TeeErrorCode GetValue(const std::string& name,
                        std::string* value,
                        const bool identity_decrypt = true);
  TeeErrorCode ListAll(const std::string& pattern,
                       tee::StorageListAllResponse* res);
  TeeErrorCode CheckExist(const std::string& name, bool* exist);

 private:
  // Hide construction functions
  StorageTrustedBridge() {}
  StorageTrustedBridge(const StorageTrustedBridge&);
  void operator=(StorageTrustedBridge const&);

  tee::StorageAuth auth_;
};

}  // namespace trusted
}  // namespace tee

#endif  // SERVER_TRUSTED_TRUSTED_STORAGE_H_
