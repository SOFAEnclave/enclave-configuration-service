#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "gflags/gflags.h"

#include "aecs/error.h"

#include "common/kubeconfig_parser.h"
#include "serviceadmin/serviceadmin_grpc_client.h"
#include "serviceadmin/serviceadmin_secret_policy.h"

#include "./aecs_admin.pb.h"

using aecs::client::ServiceAdminClient;
using kubetee::utils::FsReadString;

static const char kVersion[] = "v1";
static const char kUsage[] =
    "serviceadmin --action <sub-command> [option-flags ...]\n"
    "\nSub Commands:\n"
    "\tcreate        Create enclave secrets specified in yaml file\n"
    "\tdestroy       Destroy an enclave secret by service and secret name\n"
    "\tlist          List all enclave secrets or special one by name\n"
    "\tpreparedata   Prepare the initialized data for all type of secrets\n"
    "\tgetpub        Get RSA key pair of certificate secret public key by name";

// Define the command line options
DEFINE_string(action, "", "Sub command to be executed");
DEFINE_string(config, "", "Service Administrator identity RSA private key");
DEFINE_string(password, "", "Service Administrator password");
DEFINE_string(secret, "", "The enclave secret name to be destroy or list");
DEFINE_string(policy, "", "Yaml policy file for creating enclave secrets");
DEFINE_bool(update, false, "Allow update existed secret when create secret");

// Define the options for preparedata
// PEM file in PKCS#1 format: -----BEGIN RSA PUBLIC KEY-----
DEFINE_string(secrettype, "", "Specify the secret type, aes|rsa|sm2|cert");
DEFINE_string(pubfile, "", "Input RSA/SM2 public key file");
DEFINE_string(privfile, "", "Input RSA/SM2 private key file");

// The action handlers
TeeErrorCode DoCreateEnclaveSecret(const kubetee::KubeConfig& conf,
                                   ServiceAdminClient* aecs_client) {
  CreateEnclaveSecretRequest req;
  CreateEnclaveSecretResponse res;

  // Parse the enclave secret policies from yaml file
  kubetee::SecretsParseResult result;
  aecs::client::SecretPolicyParser policy_parser(FLAGS_policy);
  TEE_CHECK_RETURN(policy_parser.Parse(&result));

  for (int i = 0; i < result.secrets_size(); i++) {
    std::string secret_name = result.secrets()[i].spec().secret_name();
    std::string service_name = result.secrets()[i].spec().service_name();
    TEE_LOG_INFO("Create the secret[%d]: %s/%s", i, service_name.c_str(),
                 secret_name.c_str());
    req.mutable_secret()->CopyFrom(result.secrets()[i]);
    std::string secret_json;
    PB2JSON(req.secret(), &secret_json);
    TEE_LOG_DEBUG("Secret Detail: %s", secret_json.c_str());
    if (service_name != conf.name()) {
      TEE_LOG_ERROR("Different service name in kubeconfig and policy file");
      return AECS_ERROR_SECRET_CREATE_MISMATCH_SERVICE_NAME;
    }
    TEE_LOG_INFO("Update Secret: %s", FLAGS_update ? "true" : "fasle");
    req.set_is_update(FLAGS_update);
    if (aecs_client->CreateEnclaveSecret(service_name, req, &res)) {
      TEE_LOG_ERROR("Fail to create secret: %s", secret_name.c_str());
    }
  }
  return TEE_SUCCESS;
}

TeeErrorCode DoDestroyEnclaveSecret(const kubetee::KubeConfig& conf,
                                    ServiceAdminClient* aecs_client) {
  DestroyEnclaveSecretRequest req;
  DestroyEnclaveSecretResponse res;

  req.set_secret_name(FLAGS_secret);
  TEE_CHECK_RETURN(aecs_client->DestroyEnclaveSecret(conf.name(), req, &res));
  return TEE_SUCCESS;
}

TeeErrorCode DoListEnclaveSecret(const kubetee::KubeConfig& conf,
                                 ServiceAdminClient* aecs_client) {
  ListEnclaveSecretRequest req;
  ListEnclaveSecretResponse res;

  req.set_secret_name(FLAGS_secret);
  TEE_CHECK_RETURN(aecs_client->ListEnclaveSecret(conf.name(), req, &res));

  // Simply list the json string of message
  std::string res_json_str;
  PB2JSON(res, &res_json_str);
  printf("[Secrets] %s\n", res_json_str.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode DoGetEnclaveSecretPublic(const kubetee::KubeConfig& conf,
                                      ServiceAdminClient* aecs_client) {
  GetEnclaveSecretPublicRequest req;
  GetEnclaveSecretPublicResponse res;

  kubetee::common::DataBytes nonce;
  req.set_service_name(conf.name());
  req.set_secret_name(FLAGS_secret);
  req.set_nonce(nonce.Randomize(16).ToHexStr().GetStr());
  TEE_CHECK_RETURN(aecs_client->GetEnclaveSecretPublic(req, &res));
  TEE_LOG_INFO("Get public key, nonce=%s", req.nonce().c_str());

  // Verify the signature
  const std::string& public_key = res.auth_ra_report().pem_public_key();
  // use the req.nonce here to avoid the comparation to res.nonce()
  std::string signed_str = res.secret_public() + req.nonce();
  kubetee::common::AsymmetricCrypto asymmetric_crypto;
  kubetee::common::DataBytes signature(res.signature_b64());
  bool sm_mode = asymmetric_crypto.isSmMode(public_key);
  TEE_CHECK_RETURN(asymmetric_crypto.Verify(
      public_key, signed_str, signature.FromBase64().GetStr(), sm_mode));

  // Convert the json secret to protobuf message and back to json string
  kubetee::EnclaveSecret secret_public_pb;
  std::string secret_public_str;
  JSON2PB(res.secret_public(), &secret_public_pb);
  PB2JSON(secret_public_pb, &secret_public_str);
  printf("[Secret Public] %s\n", secret_public_str.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode DoPrepareSecretData() {
  // This function is to prepare secret initialized data
  // based on local inputs and output to console only.
  const std::string type = FLAGS_secrettype;
  std::string output_json;
  if (type == "rsa") {
    kubetee::AsymmetricKeyPair keypair;
    std::string* ppubkey = keypair.mutable_public_key();
    std::string* pprivkey = keypair.mutable_private_key();
    TEE_CHECK_RETURN(FsReadString(FLAGS_pubfile, ppubkey));
    TEE_CHECK_RETURN(FsReadString(FLAGS_privfile, pprivkey));
    PB2JSON(keypair, &output_json);
    printf("====JSON:\n%s\n", output_json.c_str());
  } else if (type == "sm2") {
    kubetee::AsymmetricKeyPair keypair;
    std::string keypair_json;
    std::string* ppubkey = keypair.mutable_public_key();
    std::string* pprivkey = keypair.mutable_private_key();
    TEE_CHECK_RETURN(FsReadString(FLAGS_pubfile, ppubkey));
    TEE_CHECK_RETURN(FsReadString(FLAGS_privfile, pprivkey));
    PB2JSON(keypair, &output_json);
    printf("====JSON:\n%s\n", output_json.c_str());
  } else {
    TEE_LOG_ERROR("Do not support secret type: %s", FLAGS_secrettype);
    return AECS_ERROR_SECRET_CREATE_UNSUPPORTED_TYPE;
  }

  kubetee::common::DataBytes output_b64(output_json);
  printf("====BASE64:\n%s\n", output_b64.ToBase64().GetStr().c_str());
  return TEE_SUCCESS;
}

// Main start
int main(int argc, char** argv) {
  gflags::SetVersionString(kVersion);
  gflags::SetUsageMessage(kUsage);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Prepare secret initialized data locally
  // This action don't need configuration file and GRPC
  if (FLAGS_action == "preparedata") {
    return DoPrepareSecretData();
  }

  // Firstly, parse the kubeconfig file for the administrator
  TEE_LOG_INFO("Load kubeconfig file: %s", FLAGS_config.c_str());
  kubetee::KubeConfig conf;
  aecs::client::KubeConfigParser parser(FLAGS_config);
  TEE_CHECK_RETURN(parser.Parse(&conf));

  // Then, create the secure client connect to the server
  // to avoid to to this in each handler function.
  TEE_LOG_INFO("Connecting to %s", conf.server_endpoint().c_str());
  ServiceAdminClient aecs_client(conf, FLAGS_password);
  aecs_client.GetAecsStatus();

  // Do real things for the specified sub command
  if (FLAGS_action == "create") {
    TEE_CHECK_RETURN(DoCreateEnclaveSecret(conf, &aecs_client));
  } else if (FLAGS_action == "destroy") {
    TEE_CHECK_RETURN(DoDestroyEnclaveSecret(conf, &aecs_client));
  } else if (FLAGS_action == "list") {
    TEE_CHECK_RETURN(DoListEnclaveSecret(conf, &aecs_client));
  } else if (FLAGS_action == "getpub") {
    TEE_CHECK_RETURN(DoGetEnclaveSecretPublic(conf, &aecs_client));
  } else {
    TEE_LOG_ERROR("Invalid action: %s", FLAGS_action.c_str());
    return AECS_ERROR_PARAMETER_INVALID_ACTION;
  }

  return 0;
}
