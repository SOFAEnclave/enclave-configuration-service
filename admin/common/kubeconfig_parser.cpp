#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"
#include "common/kubeconfig_parser.h"

static const char kConfAdmin[] = "administrator";
static const char kConfServer[] = "aecsServer";
static const char kConfServerInfo[] = "verifyPolicy";

namespace aecs {
namespace client {

KubeConfigParser::KubeConfigParser(const std::string filename) {
  TEE_LOG_DEBUG("Load YAML file: %s", filename.c_str());
  try {
    doc_ = YAML::LoadFile(filename);
  } catch (const YAML::ParserException& e) {
    TEE_LOG_ERROR("Fail to load YAML file: %s", e.what());
  }
}

std::string KubeConfigParser::GetStr(const YAML::Node& node) {
  return (node) ? node.as<std::string>() : "";
}

TeeErrorCode KubeConfigParser::ParseAdmin(const YAML::Node& node,
                                          kubetee::KubeConfig* conf) {
  conf->set_name(GetStr(node["name"]));
  conf->set_identity_key(GetStr(node["identityKey"]));
  return TEE_SUCCESS;
}

TeeErrorCode KubeConfigParser::ParseServerInfo(const YAML::Node& node,
                                               kubetee::KubeConfig* conf) {
  kubetee::UnifiedAttestationAttributes* attr =
      conf->mutable_server_policy()->add_main_attributes();
  attr->set_hex_ta_measurement(GetStr(node["mrenclave"]));
  attr->set_hex_signer(GetStr(node["mrsigner"]));
  attr->set_hex_prod_id(GetStr(node["prodID"]));
  attr->set_str_min_isvsvn(GetStr(node["minIsvSvn"]));
  attr->set_hex_user_data(GetStr(node["user_data"]));
  attr->set_hex_spid(GetStr(node["spid"]));
  return TEE_SUCCESS;
}

TeeErrorCode KubeConfigParser::ParseServer(const YAML::Node& node,
                                           kubetee::KubeConfig* conf) {
  if (!node[kConfServerInfo]) {
    TEE_LOG_ERROR("There is no '%s' field", kConfServerInfo);
    return AECS_ERROR_PARAMETER_KUBECONFIG_PARSE;
  }

  conf->set_client_rpc_secure(GetStr(node["clientRpcSecure"]));
  conf->set_client_key(GetStr(node["clientKey"]));
  conf->set_client_cert(GetStr(node["clientCert"]));
  conf->set_client_ca(GetStr(node["clientCA"]));
  conf->set_server_endpoint(GetStr(node["serverEndpoint"]));
  TEE_CHECK_RETURN(ParseServerInfo(node[kConfServerInfo], conf));
  return TEE_SUCCESS;
}

TeeErrorCode KubeConfigParser::Parse(kubetee::KubeConfig* conf) {
  // Maybe the yaml is not loaded successfully
  if (doc_.IsNull()) {
    TEE_LOG_ERROR_TRACE();
    return AECS_ERROR_PARAMETER_KUBECONFIG_PARSE;
  }

  // Must be the Config kind yaml file
  static constexpr char kYamlKindConfig[] = "Config";
  if (GetStr(doc_["kind"]) != kYamlKindConfig) {
    TEE_LOG_ERROR("File is not of '%s' kind", kYamlKindConfig);
    return AECS_ERROR_PARAMETER_KUBECONFIG_PARSE;
  }

  // Check the top layer objects
  if (!doc_[kConfAdmin]) {
    TEE_LOG_ERROR("There is no '%s' field", kConfAdmin);
    return AECS_ERROR_PARAMETER_KUBECONFIG_PARSE;
  }
  if (!doc_[kConfServer]) {
    TEE_LOG_ERROR("There is no '%s' field", kConfServer);
    return AECS_ERROR_PARAMETER_KUBECONFIG_PARSE;
  }

  // Anyway, use try-catch to make sure there is no panic
  // Although we have already enough check to avoid this
  try {
    TEE_CHECK_RETURN(ParseAdmin(doc_[kConfAdmin], conf));
    TEE_CHECK_RETURN(ParseServer(doc_[kConfServer], conf));
  } catch (std::exception& e) {
    TEE_LOG_ERROR("Fail to parse kubeconfig file: %s", e.what());
    return AECS_ERROR_PARAMETER_KUBECONFIG_PARSE;
  }

  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
