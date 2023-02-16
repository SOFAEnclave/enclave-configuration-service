#ifndef SERVER_TRUSTED_TRUSTED_STORAGE_H_
#define SERVER_TRUSTED_TRUSTED_STORAGE_H_

#include <string>

#include "unified_attestation/ua_trusted.h"

#include "./aecs.pb.h"

namespace kubetee {
namespace trusted {

class StorageTrustedBridge {
 public:
  static StorageTrustedBridge& GetInstance() {
    static StorageTrustedBridge instance_;
    return instance_;
  }

  TeeErrorCode SetAuth(const kubetee::StorageAuth& auth,
                       const bool allow_update = false);
  const kubetee::StorageAuth& GetAuth() {
    return auth_;
  }

  TeeErrorCode Create(const std::string& name,
                      const std::string& value,
                      const bool identity_encrypt = true);
  TeeErrorCode Update(const std::string& name,
                      const std::string& value,
                      const bool identity_encrypt = true);
  TeeErrorCode Delete(const std::string& name, const bool is_prefix = true);
  TeeErrorCode GetValue(const std::string& name,
                        std::string* value,
                        const bool identity_decrypt = true);
  TeeErrorCode ListAll(const std::string& prefix,
                       kubetee::StorageListAllResponse* res);
  TeeErrorCode CheckExist(const std::string& name, bool* exist);

 private:
  // Hide construction functions
  StorageTrustedBridge() {}
  StorageTrustedBridge(const StorageTrustedBridge&);
  void operator=(StorageTrustedBridge const&);

  bool CheckEmptyAuth();
  TeeErrorCode StorageCreate(const std::string& name,
                             const std::string& value,
                             const bool force_create,
                             const bool identity_encrypt);

  kubetee::StorageAuth auth_;
};

}  // namespace trusted
}  // namespace kubetee

#endif  // SERVER_TRUSTED_TRUSTED_STORAGE_H_
