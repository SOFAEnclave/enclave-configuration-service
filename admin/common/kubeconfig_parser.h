#ifndef ADMIN_COMMON_KUBECONFIG_PARSER_H_
#define ADMIN_COMMON_KUBECONFIG_PARSER_H_

#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "yaml-cpp/yaml.h"

#include "./aecs_admin.pb.h"

namespace aecs {
namespace client {

class KubeConfigParser {
 public:
  explicit KubeConfigParser(const std::string filename);

  // Parse the AECS or enclave serivce administrator kubeconfig file
  TeeErrorCode Parse(kubetee::KubeConfig* conf);

 private:
  std::string GetStr(const YAML::Node& node);
  TeeErrorCode ParseAdmin(const YAML::Node& node, kubetee::KubeConfig* conf);
  TeeErrorCode ParseServer(const YAML::Node& node, kubetee::KubeConfig* conf);
  TeeErrorCode ParseServerInfo(const YAML::Node& node,
                               kubetee::KubeConfig* conf);

  YAML::Node doc_;
};

}  // namespace client
}  // namespace aecs

#endif  // ADMIN_COMMON_KUBECONFIG_PARSER_H_
