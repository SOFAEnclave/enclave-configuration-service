#ifndef ADMIN_SERVICEADMIN_SERVICEADMIN_SECRET_POLICY_H_
#define ADMIN_SERVICEADMIN_SERVICEADMIN_SECRET_POLICY_H_

#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "yaml-cpp/yaml.h"

#include "./aecs_admin.pb.h"

namespace aecs {
namespace client {

class SecretPolicyParser {
 public:
  explicit SecretPolicyParser(const std::string filename);

  // Parse the enclave service secret policy file
  TeeErrorCode Parse(kubetee::SecretsParseResult* secrets);

 private:
  std::string GetStr(const YAML::Node& node);
  TeeErrorCode ParseSecret(const YAML::Node& node,
                           kubetee::EnclaveSecret* secret);
  TeeErrorCode ParseSecretPolicy(const YAML::Node& node,
                                 kubetee::EnclaveSecretPolicy* policy);
  kubetee::EnclaveSecretType ParseSecretType(const YAML::Node& node);

  YAML::Node doc_;
};

}  // namespace client
}  // namespace aecs

#endif  // ADMIN_SERVICEADMIN_SERVICEADMIN_SECRET_POLICY_H_
