#ifndef SERVER_UNTRUSTED_UNTRUSTED_AECS_CONFIG_H_
#define SERVER_UNTRUSTED_UNTRUSTED_AECS_CONFIG_H_

#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/untrusted_config.h"

namespace aecs {
namespace untrusted {

TeeErrorCode AecsGetRpcConfig(std::string* ssl_secure,
                              std::string* ssl_ca,
                              std::string* ssl_key,
                              std::string* ssl_cert);

TeeErrorCode AecsGetEnvConfig(std::string* root_server,
                              std::string* root_rpc,
                              std::string* rpc_port);

}  // namespace untrusted
}  // namespace aecs

#endif  // SERVER_UNTRUSTED_UNTRUSTED_AECS_CONFIG_H_
