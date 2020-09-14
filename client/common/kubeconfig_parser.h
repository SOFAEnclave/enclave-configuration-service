#ifndef CLIENT_COMMON_KUBECONFIG_PARSER_H_
#define CLIENT_COMMON_KUBECONFIG_PARSER_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/type.h"

#include "yaml-cpp/yaml.h"

#include "./aecs_admin.pb.h"

namespace aecs {
namespace client {

class KubeConfigParser {
 public:
  explicit KubeConfigParser(const std::string filename);

  // Parse the AECS or enclave serivce administrator kubeconfig file
  TeeErrorCode Parse(tee::KubeConfig* conf);

 private:
  std::string GetStr(const YAML::Node& node);
  TeeErrorCode ParseAdmin(const YAML::Node& node, tee::KubeConfig* conf);
  TeeErrorCode ParseServer(const YAML::Node& node, tee::KubeConfig* conf);
  TeeErrorCode ParseServerInfo(const YAML::Node& node, tee::KubeConfig* conf);

  YAML::Node doc_;
};

}  // namespace client
}  // namespace aecs

#endif  // CLIENT_COMMON_KUBECONFIG_PARSER_H_
