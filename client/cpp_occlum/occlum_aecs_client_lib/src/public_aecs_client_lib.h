#ifndef PUBLIC_AECS_CLIENT_LIB_H_
#define PUBLIC_AECS_CLIENT_LIB_H_

#include <string>

#include "aecs.pb.h"
#include "attestation/common/error.h"

TeeErrorCode VerifyAecsEnclave(
    const kubetee::UnifiedAttestationAuthReport& auth,
    const std::string& json_policy);

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode aecs_client_get_public_secret_to_file(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& nonce,
    const std::string& save_file_name);

TeeErrorCode aecs_client_get_public_secret(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& nonce,
    std::string* secret);

#ifdef __cplusplus
}
#endif

#endif  // PUBLIC_AECS_CLIENT_LIB_H_