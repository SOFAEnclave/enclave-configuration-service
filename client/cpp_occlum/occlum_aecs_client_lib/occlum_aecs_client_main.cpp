#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/error.h"

#include "gflags/gflags.h"

#include "./occlum_aecs_client_lib_c.h"
#include "./public_aecs_client_lib_c.h"

static const char kVersion[] = "v1";
static const char kUsage[] =
    "aecs_client_test_service --action <sub-command> [option-flags ...]\n"
    "\nSub Commands:\n"
    "\tcreate      Creates trusted application bound secrets by yaml conf\n"
    "\tdestroy     Destroy a trusted application bound secret by name\n"
    "\tget         Get secret created by serivceadmin or this TA\n"
    "\tgetpub      Get public key of secret\n";

// Define the command line options
DEFINE_string(action, "", "action name [create/destroy/get]");
DEFINE_string(endpoint, "", "AECS server endpoint");
DEFINE_string(service, "", "service name");
DEFINE_string(secret, "", "secret name");
DEFINE_string(nonce, "", "nonce to prevent replay attacks");
DEFINE_string(policy, "", "yaml policy file when create secret");
DEFINE_string(output, "", "output file to save secret when get/getpub");

#define CHECK_FLAGS(f, m)                      \
  do {                                         \
    if (f.empty()) {                           \
      TEE_LOG_ERROR(m);                        \
      return AECS_ERROR_PARAMETER_FLAGS_EMPTT; \
    }                                          \
  } while (0)

//=============================================================
// The action handlers
//=============================================================
static int DoCreateSecret() {
  std::string aecs_ra_policy = "";
  printf("[Get secret public key]\n");
  printf("  AECS Server: %s\n", FLAGS_endpoint.c_str());
  printf("  Template File: %s\n", FLAGS_policy.c_str());

  // Use the C-ABI interface to get secret public key
  int ret = aecs_client_create_ta_secret(
      FLAGS_endpoint.c_str(), aecs_ra_policy.c_str(), FLAGS_policy.c_str());
  if (ret != 0) {
    printf("Fail to create secret: %d!\n", ret);
    return ret;
  }

  return 0;
}

static int DoDestroySecret() {
  std::string aecs_ra_policy = "";
  printf("[Get secret public key]\n");
  printf("  AECS Server: %s\n", FLAGS_endpoint.c_str());
  printf("  Secret Name: %s\n", FLAGS_secret.c_str());

  // Use the C-ABI interface to get secret public key
  int ret = aecs_client_destroy_ta_secret(
      FLAGS_endpoint.c_str(), aecs_ra_policy.c_str(), FLAGS_secret.c_str());
  if (ret != 0) {
    printf("Fail to destroy secret: %d!\n", ret);
    return ret;
  }

  return 0;
}

static int DoGetSecret() {
  std::string aecs_ra_policy = "";
  printf("[Get secret]\n");
  printf("  AECS Server: %s\n", FLAGS_endpoint.c_str());
  printf("  Service Name: %s\n", FLAGS_action.c_str());
  printf("  Secret Name: %s\n", FLAGS_secret.c_str());
  printf("  Nonce: %s\n", FLAGS_nonce.c_str());
  printf("  File Name: %s\n", FLAGS_output.c_str());

  // Use the C-ABI interface to get secret
  int ret = aecs_client_get_secret_and_save_file(
      FLAGS_endpoint.c_str(), aecs_ra_policy.c_str(), FLAGS_service.c_str(),
      FLAGS_secret.c_str(), FLAGS_nonce.c_str(), FLAGS_output.c_str());
  if (ret != 0) {
    printf("Fail to get secret from aecs: %d!\n", ret);
    return ret;
  }

  // For test only, print the secret for check
  std::string secret_str;
  using kubetee::utils::FsReadString;
  ret = FsReadString(FLAGS_output, &secret_str);
  if (ret != 0) {
    printf("Fail to read the secret file: %d\n", ret);
    return ret;
  } else {
    printf("[Secret] %s\n", secret_str.c_str());
  }

  return 0;
}

static int DoGetSecretPublic() {
  std::string aecs_ra_policy = "";
  printf("[Get secret public key]\n");
  printf("  AECS Server: %s\n", FLAGS_endpoint.c_str());
  printf("  Service Name: %s\n", FLAGS_action.c_str());
  printf("  Secret Name: %s\n", FLAGS_secret.c_str());
  printf("  Nonce: %s\n", FLAGS_nonce.c_str());
  printf("  File Name: %s\n", FLAGS_output.c_str());

  // Use the C-ABI interface to get secret public key
  int ret = aecs_client_get_public_secret_and_save_file(
      FLAGS_endpoint.c_str(), aecs_ra_policy.c_str(), FLAGS_service.c_str(),
      FLAGS_secret.c_str(), FLAGS_nonce.c_str(), FLAGS_output.c_str());
  if (ret != 0) {
    printf("Fail to get secret public key from aecs: %d!\n", ret);
    return ret;
  }

  // For test only, print the secret for check
  std::string secret_str;
  using kubetee::utils::FsReadString;
  ret = FsReadString(FLAGS_output, &secret_str);
  if (ret != 0) {
    printf("Fail to read the secret file: %d\n", ret);
    return ret;
  } else {
    printf("[Secret] %s\n", secret_str.c_str());
  }

  return 0;
}

// Main Start
int main(int argc, char** argv) {
  // Initialize the gflags
  gflags::SetVersionString(kVersion);
  gflags::SetUsageMessage(kUsage);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Check the flags
  CHECK_FLAGS(FLAGS_action, "Empty action");
  CHECK_FLAGS(FLAGS_endpoint, "Empty endpoint");

  int ret = -1;
  if (FLAGS_action == "create") {
    ret = DoCreateSecret();
  } else if (FLAGS_action == "destroy") {
    ret = DoDestroySecret();
  } else if (FLAGS_action == "get") {
    ret = DoGetSecret();
  } else if (FLAGS_action == "getpub") {
    ret = DoGetSecretPublic();
  } else {
    TEE_LOG_ERROR("Invalid action: %s", FLAGS_action.c_str());
    ret = AECS_ERROR_PARAMETER_INVALID_ACTION;
  }

  printf("Action done: %d\n", ret);
  return ret;
}
