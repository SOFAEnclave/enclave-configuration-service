#ifndef CLIENT_SERVICEADMIN_SERVICEADMIN_SECRET_POLICY_H_
#define CLIENT_SERVICEADMIN_SERVICEADMIN_SECRET_POLICY_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/type.h"

#include "yaml-cpp/yaml.h"

#include "./aecs_admin.pb.h"

namespace aecs {
namespace client {

class SecretPolicyParser {
 public:
  explicit SecretPolicyParser(const std::string filename);

  // Parse the enclave service secret policy file
  TeeErrorCode Parse(tee::SecretsParseResult* secrets);

 private:
  std::string GetStr(const YAML::Node& node);
  TeeErrorCode ParseSecret(const YAML::Node& node, tee::EnclaveSecret* secret);
  TeeErrorCode ParseSecretPolicy(const YAML::Node& node,
                                 tee::EnclaveSecretPolicy* policy);
  tee::EnclaveSecretType ParseSecretType(const YAML::Node& node);

  YAML::Node doc_;
};

}  // namespace client
}  // namespace aecs

#endif  // CLIENT_SERVICEADMIN_SERVICEADMIN_SECRET_POLICY_H_
