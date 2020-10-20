#include <string>

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "gflags/gflags.h"
#include "google/protobuf/util/json_util.h"  // for message to json

#include "common/kubeconfig_parser.h"
#include "serviceadmin/serviceadmin_grpc_client.h"
#include "serviceadmin/serviceadmin_secret_policy.h"

#include "./aecs_admin.pb.h"

using aecs::client::ServiceAdminClient;
using google::protobuf::util::MessageToJsonString;

static const char kVersion[] = "v1";
static const char kUsage[] =
    "serviceadmin --action <sub-command> [option-flags ...]\n"
    "\nSub Commands:\n"
    "\tcreate        Create enclave secrets specified in yaml file\n"
    "\tdestroy       Destroy an enclave secret by service and secret name\n"
    "\tlist          List all enclave secrets or special one by name";

// Define the command line options
DEFINE_string(action, "", "Sub command to be executed");
DEFINE_string(config, "", "Service Administrator identity RSA private key");
DEFINE_string(password, "", "Service Administrator password");
DEFINE_string(secret, "", "The enclave secret name to be destroy or list");
DEFINE_string(policy, "", "Yaml policy file for creating enclave secrets");

// The action handlers
TeeErrorCode DoCreateEnclaveSecret(const tee::KubeConfig& conf,
                                   ServiceAdminClient* aecs_client) {
  CreateEnclaveSecretRequest req;
  CreateEnclaveSecretResponse res;

  // Parse the enclave secret policies from yaml file
  tee::SecretsParseResult result;
  aecs::client::SecretPolicyParser policy_parser(FLAGS_policy);
  TEE_CHECK_RETURN(policy_parser.Parse(&result));

  for (int i = 0; i < result.secrets_size(); i++) {
    std::string secret_name = result.secrets()[i].spec().secret_name();
    std::string service_name = result.secrets()[i].spec().service_name();
    TEE_LOG_INFO("Create the secret[%d]: %s-%s",
                 i,
                 secret_name.c_str(),
                 service_name.c_str());
    req.mutable_secret()->CopyFrom(result.secrets()[i]);
    if (service_name != conf.name()) {
      TEE_LOG_ERROR("Different service name in kubeconfig and policy file");
      return TEE_ERROR_PARAMETERS;
    }
    TEE_CHECK_RETURN(aecs_client->CreateEnclaveSecret(service_name, req, &res));
  }
  return TEE_SUCCESS;
}

TeeErrorCode DoDestroyEnclaveSecret(const tee::KubeConfig& conf,
                                    ServiceAdminClient* aecs_client) {
  DestroyEnclaveSecretRequest req;
  DestroyEnclaveSecretResponse res;

  req.set_secret_name(FLAGS_secret);
  TEE_CHECK_RETURN(aecs_client->DestroyEnclaveSecret(conf.name(), req, &res));
  return TEE_SUCCESS;
}

TeeErrorCode DoListEnclaveSecret(const tee::KubeConfig& conf,
                                 ServiceAdminClient* aecs_client) {
  ListEnclaveSecretRequest req;
  ListEnclaveSecretResponse res;

  req.set_secret_name(FLAGS_secret);
  TEE_CHECK_RETURN(aecs_client->ListEnclaveSecret(conf.name(), req, &res));

  // Simply list the json string of message
  std::string res_json_str;
  MessageToJsonString(res, &res_json_str);
  printf("[Secrets] %s\n", res_json_str.c_str());
  return TEE_SUCCESS;
}

// Main start
int main(int argc, char** argv) {
  gflags::SetVersionString(kVersion);
  gflags::SetUsageMessage(kUsage);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Firstly, parse the kubeconfig file for the administrator
  TEE_LOG_INFO("Load kubeconfig file: %s", FLAGS_config.c_str());
  tee::KubeConfig conf;
  aecs::client::KubeConfigParser parser(FLAGS_config);
  TEE_CHECK_RETURN(parser.Parse(&conf));

  // Get the base64 items
  tee::common::DataBytes ca(conf.client_ca());
  tee::common::DataBytes key(conf.client_key());
  tee::common::DataBytes cert(conf.client_cert());
  tee::common::DataBytes ikey(conf.identity_key());
  std::string password_hash_str;
  if (!FLAGS_password.empty()) {
    tee::common::DataBytes password(FLAGS_password);
    password_hash_str = password.ToSHA256().ToHexStr().GetStr();
  }

  // Then, create the secure client connect to the server
  // to avoid to to this in each handler function.
  TEE_LOG_INFO("Connecting to %s", conf.server_endpoint().c_str());
  ServiceAdminClient secure_client(conf.server_endpoint(),
                                   ca.FromBase64().GetStr(),
                                   key.FromBase64().GetStr(),
                                   cert.FromBase64().GetStr(),
                                   ikey.FromBase64().GetStr(),
                                   password_hash_str,
                                   conf.server_info());
  secure_client.GetServerPublicKey(conf.name());

  // Do real things for the specified sub command
  if (FLAGS_action == "create") {
    TEE_CHECK_RETURN(DoCreateEnclaveSecret(conf, &secure_client));
  } else if (FLAGS_action == "destroy") {
    TEE_CHECK_RETURN(DoDestroyEnclaveSecret(conf, &secure_client));
  } else if (FLAGS_action == "list") {
    TEE_CHECK_RETURN(DoListEnclaveSecret(conf, &secure_client));
  } else {
    TEE_LOG_ERROR("Invalid action: %s", FLAGS_action.c_str());
    return TEE_ERROR_PARAMETERS;
  }

  return 0;
}
