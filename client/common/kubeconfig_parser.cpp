#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"

#include "client/common/kubeconfig_parser.h"

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
                                          tee::KubeConfig* conf) {
  conf->set_name(GetStr(node["name"]));
  conf->set_identity_key(GetStr(node["identityKey"]));
  return TEE_SUCCESS;
}

TeeErrorCode KubeConfigParser::ParseServerInfo(const YAML::Node& node,
                                               tee::KubeConfig* conf) {
  tee::EnclaveInformation* info = conf->mutable_server_info()->add_entries();
  info->set_hex_mrenclave(GetStr(node["mrenclave"]));
  info->set_hex_mrsigner(GetStr(node["mrsigner"]));
  info->set_hex_prod_id(GetStr(node["prodID"]));
  info->set_hex_min_isvsvn(GetStr(node["minIsvSvn"]));
  info->set_hex_user_data(GetStr(node["user_data"]));
  info->set_hex_spid(GetStr(node["spid"]));
  return TEE_SUCCESS;
}

TeeErrorCode KubeConfigParser::ParseServer(const YAML::Node& node,
                                           tee::KubeConfig* conf) {
  if (!node[kConfServerInfo]) {
    TEE_LOG_ERROR("There is no '%s' field", kConfServerInfo);
    return TEE_ERROR_PARAMETERS;
  }

  conf->set_client_key(GetStr(node["clientKey"]));
  conf->set_client_cert(GetStr(node["clientCert"]));
  conf->set_client_ca(GetStr(node["clientCA"]));
  conf->set_server_endpoint(GetStr(node["serverEndpoint"]));
  TEE_CHECK_RETURN(ParseServerInfo(node[kConfServerInfo], conf));
  return TEE_SUCCESS;
}

TeeErrorCode KubeConfigParser::Parse(tee::KubeConfig* conf) {
  // Maybe the yaml is not loaded successfully
  if (doc_.IsNull()) {
    TEE_LOG_ERROR_TRACE();
    return TEE_ERROR_UNEXPECTED;
  }

  // Must be the Config kind yaml file
  static constexpr char kYamlKindConfig[] = "Config";
  if (GetStr(doc_["kind"]) != kYamlKindConfig) {
    TEE_LOG_ERROR("File is not of '%s' kind", kYamlKindConfig);
    return TEE_ERROR_UNEXPECTED;
  }

  // Check the top layer objects
  if (!doc_[kConfAdmin]) {
    TEE_LOG_ERROR("There is no '%s' field", kConfAdmin);
    return TEE_ERROR_PARAMETERS;
  }
  if (!doc_[kConfServer]) {
    TEE_LOG_ERROR("There is no '%s' field", kConfServer);
    return TEE_ERROR_PARAMETERS;
  }

  // Anyway, use try-catch to make sure there is no panic
  // Although we have already enough check to avoid this
  try {
    TEE_CHECK_RETURN(ParseAdmin(doc_[kConfAdmin], conf));
    TEE_CHECK_RETURN(ParseServer(doc_[kConfServer], conf));
  } catch (std::exception& e) {
    TEE_LOG_ERROR("Fail to parse kubeconfig file: %s", e.what());
    return TEE_ERROR_PARAMETERS;
  }

  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
