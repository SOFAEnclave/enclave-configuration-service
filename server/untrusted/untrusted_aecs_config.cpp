#include <string>

#include "untrusted/untrusted_aecs_config.h"

#include "aecs/error.h"

#include "./aecs.pb.h"

namespace aecs {
namespace untrusted {

TeeErrorCode AecsGetRpcConfig(std::string* ssl_secure,
                              std::string* ssl_ca,
                              std::string* ssl_key,
                              std::string* ssl_cert) {
  // Load configurations form config file
  ssl_secure->assign(AECS_CONF_STR(kAecsConfRpcSslSecure));
  if (*ssl_secure == kConfValueEnable) {
    ssl_ca->assign(AECS_CONF_FILE_STR(kAecsConfRpcSslCa));
    ssl_key->assign(AECS_CONF_FILE_STR(kAecsConfRpcSslKey));
    ssl_cert->assign(AECS_CONF_FILE_STR(kAecsConfRpcSslCert));
    if (ssl_ca->empty() || ssl_key->empty() || ssl_cert->empty()) {
      return AECS_ERROR_CONF_SSL_REQUIRED;
    }
  }
  return TEE_SUCCESS;
}

TeeErrorCode AecsGetEnvConfig(std::string* root_server,
                              std::string* root_port,
                              std::string* rpc_port) {
  // Load configurations from environment variables, and then config file
  root_server->assign(
      AECS_ENV_CONF_STR(kAecsEnvRpcRemoteServer, kAecsConfRpcRemoteServer));
  root_port->assign(
      AECS_ENV_CONF_STR(kAecsEnvRpcRemotePort, kAecsConfRpcRemotePort));
  rpc_port->assign(AECS_ENV_CONF_STR(kAecsEnvRpcPort, kAecsConfRpcPort));
  if (rpc_port->empty()) {
    return AECS_ERROR_CONF_RPC_REQUIRED;
  }
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace aecs
