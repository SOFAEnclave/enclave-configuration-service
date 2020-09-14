#ifndef SERVER_UNTRUSTED_UNTRUSTED_AECS_CONFIG_H_
#define SERVER_UNTRUSTED_UNTRUSTED_AECS_CONFIG_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/untrusted/utils/untrusted_json.h"

namespace tee {
namespace untrusted {

constexpr char kAecsConfFile[] = "aecs_server.json";

constexpr char kAecsConfBackendLib[] = "storage_backend_lib";
constexpr char kAecsConfAdminPubKey[] = "aecs_admin_pubkey";

}  // namespace untrusted
}  // namespace tee

#define AECS_CONF_STR(name) \
  JSON_CONF_STR(tee::untrusted::kAecsConfFile, tee::untrusted::name)

#endif  // SERVER_UNTRUSTED_UNTRUSTED_AECS_CONFIG_H_
