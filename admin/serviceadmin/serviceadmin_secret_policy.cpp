#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"
#include "serviceadmin/serviceadmin_secret_policy.h"

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

kubetee::EnclaveSecretType SecretPolicyParser::ParseSecretType(
    const YAML::Node& type) {
  std::string type_str = GetStr(type);
  if (type_str == "SECRET_TYPE_RSA_KEY_PAIR") {
    return kubetee::SECRET_TYPE_RSA_KEY_PAIR;
  } else if (type_str == "SECRET_TYPE_AES256_KEY") {
    return kubetee::SECRET_TYPE_AES256_KEY;
  } else if (type_str == "SECRET_TYPE_IMPORT_DATA") {
    return kubetee::SECRET_TYPE_IMPORT_DATA;
  } else if (type_str == "SECRET_TYPE_CERTIFICATE") {
    return kubetee::SECRET_TYPE_CERTIFICATE;
  } else if (type_str == "SECRET_TYPE_SM2_KEY_PAIR") {
    return kubetee::SECRET_TYPE_SM2_KEY_PAIR;
  } else if (type_str == "SECRET_TYPE_CONFIGURATIONS") {
    return kubetee::SECRET_TYPE_CONFIGURATIONS;
  } else {
    return kubetee::SECRET_TYPE_RSA_KEY_PAIR;
  }
}

TeeErrorCode SecretPolicyParser::ParseSecretPolicy(
    const YAML::Node& node, kubetee::EnclaveSecretPolicy* policy) {
  // Now, we only support the enclaveMatchAnyRules
  if (!node["enclaveMatchAnyRules"]) {
    TEE_LOG_ERROR("There is no enclave match rules");
    return AECS_ERROR_PARAMETER_POLICY_PARSE;
  }

  // Parse all the enclave match rules in policy
  for (int i = 0; i < node["enclaveMatchAnyRules"].size(); i++) {
    const YAML::Node& yaml_rule = node["enclaveMatchAnyRules"][i];
    kubetee::UnifiedAttestationAttributes* info =
        policy->mutable_policy()->add_main_attributes();
    info->set_hex_ta_measurement(GetStr(yaml_rule["mrenclave"]));
    info->set_hex_signer(GetStr(yaml_rule["mrsigner"]));
    info->set_hex_prod_id(GetStr(yaml_rule["prodID"]));
    info->set_str_min_isvsvn(GetStr(yaml_rule["minIsvSvn"]));
    info->set_hex_user_data(GetStr(yaml_rule["user_data"]));
    info->set_hex_spid(GetStr(yaml_rule["spid"]));
    info->set_bool_debug_disabled(GetStr(yaml_rule["debug_disabled"]));
  }

  return TEE_SUCCESS;
}

TeeErrorCode SecretPolicyParser::ParseSecret(const YAML::Node& node,
                                             kubetee::EnclaveSecret* secret) {
  if (!node["spec"]) {
    TEE_LOG_ERROR("There is no secret spec");
    return AECS_ERROR_PARAMETER_POLICY_PARSE;
  }

  // Parse the secret specification generic items
  const YAML::Node& yaml_spec = node["spec"];
  kubetee::EnclaveSecretSpec* secret_spec = secret->mutable_spec();
  kubetee::EnclaveSecretType secret_type = ParseSecretType(yaml_spec["type"]);
  secret_spec->set_secret_name(GetStr(yaml_spec["name"]));
  secret_spec->set_service_name(GetStr(yaml_spec["service"]));
  secret_spec->set_readonly(GetStr(yaml_spec["readonly"]));
  secret_spec->set_share(GetStr(yaml_spec["share"]));
  secret_spec->set_type(secret_type);

  // Parse the secret policy in the specification
  kubetee::EnclaveSecretPolicy* secret_policy = secret_spec->mutable_policy();
  TEE_CHECK_RETURN(ParseSecretPolicy(yaml_spec["policy"], secret_policy));

  // Parse the secret parameters in the specification
  if (yaml_spec["params"]) {
    for (int i = 0; i < yaml_spec["params"].size(); i++) {
      const YAML::Node& yaml_param = yaml_spec["params"][i];
      kubetee::EnclaveKvPair* param = secret_spec->add_params();
      param->set_key(GetStr(yaml_param["key"]));
      param->set_value(GetStr(yaml_param["value"]));
      TEE_LOG_INFO("Secret Parameter: %s=%s", param->key().c_str(),
                   param->value().c_str());
    }
  }

  // Parse the secret data
  std::string data = GetStr(node["data"]);
  if (!data.empty()) {
    secret->set_data(data);
  } else if (secret_type == kubetee::SECRET_TYPE_IMPORT_DATA) {
    TEE_LOG_ERROR("There is no secret data to be imported");
    return AECS_ERROR_PARAMETER_POLICY_PARSE;
  }

  return TEE_SUCCESS;
}

TeeErrorCode SecretPolicyParser::Parse(kubetee::SecretsParseResult* secrets) {
  // Maybe the yaml is not loaded successfully
  if (doc_.IsNull()) {
    TEE_LOG_ERROR_TRACE();
    return AECS_ERROR_PARAMETER_POLICY_PARSE;
  }

  // Must be the Policy kind yaml file
  static constexpr char kYamlKindSecretPolicy[] = "SecretPolicy";
  if (GetStr(doc_["kind"]) != kYamlKindSecretPolicy) {
    TEE_LOG_ERROR("File is not of '%s' kind", kYamlKindSecretPolicy);
    return AECS_ERROR_PARAMETER_POLICY_PARSE;
  }

  // Check the top layer objects
  static constexpr char kLabelSecrets[] = "secrets";
  if (!doc_[kLabelSecrets] || (doc_[kLabelSecrets].size() == 0)) {
    TEE_LOG_ERROR("There is no '%s' field", kLabelSecrets);
    return AECS_ERROR_PARAMETER_POLICY_PARSE;
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
    return AECS_ERROR_PARAMETER_POLICY_PARSE;
  }

  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
