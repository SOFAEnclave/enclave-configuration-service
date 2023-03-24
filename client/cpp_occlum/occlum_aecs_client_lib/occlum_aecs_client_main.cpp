#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "./occlum_aecs_client_lib_c.h"
#include "./public_aecs_client_lib_c.h"

int main(int argc, char** argv) {
  int ret = -1;

  if (argc < 6) {
    printf(
        "Usage: %s <endpoint> <service> <secret> <nonce> <filename> "
        "[--public]\n",
        argv[0]);
    return -1;
  }

  const char* policy = "";
  const char* endpoint = argv[1];
  const char* service = argv[2];
  const char* secret = argv[3];
  const char* nonce = argv[4];
  const char* filename = argv[5];
  std::string opt_public = (argc == 7) ? argv[6] : "--secret";

  printf("AECS Server: %s\n", endpoint);
  printf("Service Name: %s\n", service);
  printf("Secret Name: %s\n", secret);
  printf("Nonce: %s\n", nonce);
  printf("File Name: %s\n", filename);
  printf("Get What: %s\n", opt_public.c_str());

  if (opt_public == "--public") {
    ret = aecs_client_get_public_secret_and_save_file(endpoint, policy, service,
                                                      secret, nonce, filename);
    if (ret != 0) {
      printf("Fail to get secret from aecs: %d!\n", ret);
      return ret;
    }
  } else {
    ret = aecs_client_get_secret_and_save_file(endpoint, policy, service,
                                               secret, nonce, filename);
    if (ret != 0) {
      printf("Fail to get secret from aecs: %d!\n", ret);
      return ret;
    }
  }

  // For test only, print the secret for check
  std::string secret_str;
  using kubetee::utils::FsReadString;
  ret = FsReadString(filename, &secret_str);
  if (ret != 0) {
    printf("Fail to read the secret file: %d\n", ret);
    return ret;
  } else {
    printf("[Secret] %s\n", secret_str.c_str());
  }

  return 0;
}
