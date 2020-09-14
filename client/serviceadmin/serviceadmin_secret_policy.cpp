#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"

#include "client/serviceadmin/serviceadmin_secret_policy.h"

namespace aecs {
namespace client {

SecretPolicyParser::SecretPolicyParser(const std::string filename) {
  TEE_LOG_DEBUG("Load policy file: %s", filename.c_str());
  try {
    doc_ = YAML::LoadFile(filename);
  } catch (const YAML::ParserException& e) {
    TEE_LOG_ERROR("Fail to load policy file: %s", e.what());
  }
}

std::string SecretPolicyParser::GetStr(const YAML::Node& node) {
  return (node) ? node.as<std::string>() : "";
}

tee::EnclaveSecretType SecretPolicyParser::ParseSecretType(
    const YAML::Node& type) {
  std::string type_str = GetStr(type);
  if (type_str == "SECRET_TYPE_RSA_KEY_PAIR") {
    return tee::SECRET_TYPE_RSA_KEY_PAIR;
  } else if (type_str == "SECRET_TYPE_AES256_KEY") {
    return tee::SECRET_TYPE_AES256_KEY;
  } else if (type_str == "SECRET_TYPE_IMPORT_DATA") {
    return tee::SECRET_TYPE_IMPORT_DATA;
  } else if (type_str == "SECRET_TYPE_CERTIFICATE") {
    return tee::SECRET_TYPE_CERTIFICATE;
  } else {
    return tee::SECRET_TYPE_RSA_KEY_PAIR;
  }
}

TeeErrorCode SecretPolicyParser::ParseSecretPolicy(
    const YAML::Node& node, tee::EnclaveSecretPolicy* policy) {
  // Now, we only support the enclaveMatchAnyRules
  if (!node["enclaveMatchAnyRules"]) {
    TEE_LOG_ERROR("There is no enclave match rules");
    return TEE_ERROR_PARAMETERS;
  }

  // Parse all the enclave match rules in policy
  for (int i = 0; i < node["enclaveMatchAnyRules"].size(); i++) {
    const YAML::Node& yaml_rule = node["enclaveMatchAnyRules"][i];
    tee::EnclaveInformation* info = policy->mutable_rules()->add_entries();
    info->set_hex_mrenclave(GetStr(yaml_rule["mrenclave"]));
    info->set_hex_mrsigner(GetStr(yaml_rule["mrsigner"]));
    info->set_hex_prod_id(GetStr(yaml_rule["prodID"]));
    info->set_hex_min_isvsvn(GetStr(yaml_rule["minIsvSvn"]));
    info->set_hex_user_data(GetStr(yaml_rule["user_data"]));
    info->set_hex_spid(GetStr(yaml_rule["spid"]));
  }

  return TEE_SUCCESS;
}

TeeErrorCode SecretPolicyParser::ParseSecret(const YAML::Node& node,
                                             tee::EnclaveSecret* secret) {
  if (!node["spec"]) {
    TEE_LOG_ERROR("There is no secret spec");
    return TEE_ERROR_PARAMETERS;
  }

  // Parse the secret specification generic items
  const YAML::Node& yaml_spec = node["spec"];
  tee::EnclaveSecretSpec* secret_spec = secret->mutable_spec();
  tee::EnclaveSecretType secret_type = ParseSecretType(yaml_spec["type"]);
  secret_spec->set_secret_name(GetStr(yaml_spec["name"]));
  secret_spec->set_service_name(GetStr(yaml_spec["service"]));
  secret_spec->set_type(secret_type);

  // Parse the secret policy in the specification
  tee::EnclaveSecretPolicy* secret_policy = secret_spec->mutable_policy();
  TEE_CHECK_RETURN(ParseSecretPolicy(yaml_spec["policy"], secret_policy));

  // Only parse the secret data for SECRET_TYPE_IMPORT_DATA type
  if ((secret_type == tee::SECRET_TYPE_IMPORT_DATA)) {
    std::string data = GetStr(node["data"]);
    if (!data.empty()) {
      secret->set_data(data);
    } else {
      TEE_LOG_ERROR("There is no secret data to be imported");
      return TEE_ERROR_PARAMETERS;
    }
  }

  return TEE_SUCCESS;
}

TeeErrorCode SecretPolicyParser::Parse(tee::SecretsParseResult* secrets) {
  // Maybe the yaml is not loaded successfully
  if (doc_.IsNull()) {
    TEE_LOG_ERROR_TRACE();
    return TEE_ERROR_UNEXPECTED;
  }

  // Must be the Policy kind yaml file
  static constexpr char kYamlKindSecretPolicy[] = "SecretPolicy";
  if (GetStr(doc_["kind"]) != kYamlKindSecretPolicy) {
    TEE_LOG_ERROR("File is not of '%s' kind", kYamlKindSecretPolicy);
    return TEE_ERROR_UNEXPECTED;
  }

  // Check the top layer objects
  static constexpr char kLabelSecrets[] = "secrets";
  if (!doc_[kLabelSecrets] || (doc_[kLabelSecrets].size() == 0)) {
    TEE_LOG_ERROR("There is no '%s' field", kLabelSecrets);
    return TEE_ERROR_PARAMETERS;
  }

  // Anyway, use try-catch to make sure there is no panic
  // Although we have already enough check to avoid this
  try {
    for (int i = 0; i < doc_[kLabelSecrets].size(); i++) {
      TEE_CHECK_RETURN(
          ParseSecret(doc_[kLabelSecrets][i], secrets->add_secrets()));
    }
  } catch (std::exception& e) {
    TEE_LOG_ERROR("Fail to parse secret policy file: %s", e.what());
    return TEE_ERROR_PARAMETERS;
  }

  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
