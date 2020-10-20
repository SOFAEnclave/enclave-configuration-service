#include <string>

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "gflags/gflags.h"
#include "google/protobuf/util/json_util.h"  // for message to json

#include "aecsadmin/aecsadmin_grpc_client.h"
#include "common/kubeconfig_parser.h"

#include "./aecs_admin.pb.h"

using aecs::client::AecsAdminClient;
using google::protobuf::util::MessageToJsonString;

static const char kVersion[] = "v1";
static const char kUsage[] =
    "serviceadmin --action <sub-command> [option-flags ...]\n"
    "\nSub Commands:\n"
    "\tregister      Register a enclave service\n"
    "\tunregister    Unregister a enclave service and remove all\n"
    "\tlist          List all enclave service names\n"
    "\tprovision     Provision AECS, such as OSS authentication information";

// Define the command line options
DEFINE_string(action, "", "Sub command to be executed");
DEFINE_string(config, "", "AECS Administrator identity RSA private key");
DEFINE_string(service, "", "The enclave service name");
DEFINE_string(servicepasswordhash, "", "The password SHA256 for service");
DEFINE_string(pubkey, "", "Enclave service owner identity RSA public key");
DEFINE_string(password, "", "Password for AECS/Service administrator");
DEFINE_string(osskeyid, "", "Access key ID for ossauth sub command");
DEFINE_string(osskeysecret, "", "Access key secret for ossauth sub command");
DEFINE_string(ossbucket, "", "Bucket name for ossauth sub command");
DEFINE_string(ossendpoint, "", "Endpoint for ossauth sub command");
DEFINE_string(hostname, "", "Host name of root server for identity backup");

#define CHECK_FLAGS(f, m)          \
  do {                             \
    if (f.empty()) {               \
      TEE_LOG_ERROR(m);            \
      return TEE_ERROR_PARAMETERS; \
    }                              \
  } while (0)

// The action handlers
TeeErrorCode DoRegisterEnclaveService(AecsAdminClient* aecs_client) {
  RegisterEnclaveServiceRequest req;
  RegisterEnclaveServiceResponse res;

  // Get enclave service public key from local file
  std::string public_key;
  TEE_CHECK_RETURN(tee::untrusted::FsReadString(FLAGS_pubkey, &public_key));

  req.set_service_name(FLAGS_service);
  req.set_service_password_hash(FLAGS_servicepasswordhash);
  req.set_service_pubkey(public_key);
  TEE_CHECK_RETURN(aecs_client->RegisterEnclaveService(req, &res));
  return TEE_SUCCESS;
}

TeeErrorCode DoUnregisterEnclaveService(AecsAdminClient* aecs_client) {
  UnregisterEnclaveServiceRequest req;
  UnregisterEnclaveServiceResponse res;

  req.set_service_name(FLAGS_service);
  TEE_CHECK_RETURN(aecs_client->UnregisterEnclaveService(req, &res));
  return TEE_SUCCESS;
}

TeeErrorCode DoListEnclaveService(AecsAdminClient* aecs_client) {
  ListEnclaveServiceRequest req;
  ListEnclaveServiceResponse res;

  req.set_service_name(FLAGS_service);
  TEE_CHECK_RETURN(aecs_client->ListEnclaveService(req, &res));

  // Simply list the json string of message
  std::string res_json_str;
  MessageToJsonString(res, &res_json_str);
  printf("[Services] %s\n", res_json_str.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode DoProvision(AecsAdminClient* aecs_client) {
  AecsProvisionRequest req;
  AecsProvisionResponse res;

  // For localfs storage, oss secrets are optional
  // CHECK_FLAGS(FLAGS_osskeyid, "Empty OSS access key id");
  // CHECK_FLAGS(FLAGS_osskeysecret, "Empty OSS access key secret");
  // CHECK_FLAGS(FLAGS_ossbucket, "Empty OSS bucket name");
  // CHECK_FLAGS(FLAGS_ossendpoint, "Empty OSS endpoint");
  CHECK_FLAGS(FLAGS_hostname, "Empty host name");

  req.mutable_auth()->set_access_key_id(FLAGS_osskeyid);
  req.mutable_auth()->set_access_key_secret(FLAGS_osskeysecret);
  req.mutable_auth()->set_endpoint(FLAGS_ossendpoint);
  req.mutable_auth()->set_bucket_name(FLAGS_ossbucket);
  // host_name is used for the identity key backup name in OSS
  req.set_host_name(FLAGS_hostname);
  TEE_CHECK_RETURN(aecs_client->AecsProvision(req, &res));

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
  AecsAdminClient secure_client(conf.server_endpoint(),
                                ca.FromBase64().GetStr(),
                                key.FromBase64().GetStr(),
                                cert.FromBase64().GetStr(),
                                ikey.FromBase64().GetStr(),
                                password_hash_str,
                                conf.server_info());
  secure_client.GetServerPublicKey();

  // Do real things for the specified sub command
  if (FLAGS_action == "register") {
    TEE_CHECK_RETURN(DoRegisterEnclaveService(&secure_client));
  } else if (FLAGS_action == "unregister") {
    TEE_CHECK_RETURN(DoUnregisterEnclaveService(&secure_client));
  } else if (FLAGS_action == "list") {
    TEE_CHECK_RETURN(DoListEnclaveService(&secure_client));
  } else if (FLAGS_action == "provision") {
    TEE_CHECK_RETURN(DoProvision(&secure_client));
  } else {
    TEE_LOG_ERROR("Invalid action: %s", FLAGS_action.c_str());
    return TEE_ERROR_PARAMETERS;
  }

  return 0;
}
