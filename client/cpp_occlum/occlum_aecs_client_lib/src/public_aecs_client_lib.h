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

/// @brief Get secret public key or cert-chain and save it to file
///
/// @param aecs_server_endpoint
/// @param aecs_server_policy
/// @param secret_service
/// @param secret_name
/// @param secret_policy
/// @param nonce
/// @param save_file_name
/// @return
TeeErrorCode aecs_client_get_public_secret_to_file(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& secret_policy,
    const std::string& nonce,
    const std::string& save_file_name);

/// @brief Get secret public key or cert-chain if it exists andis allowed
///
/// @param aecs_server_endpoint
/// @param aecs_server_policy
/// @param secret_service
/// @param secret_name
/// @param secret_policy
/// @param nonce
/// @param secret_public
/// @return
TeeErrorCode aecs_client_get_public_secret(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& secret_policy,
    const std::string& nonce,
    std::string* secret_public);

#ifdef __cplusplus
}
#endif

#endif  // PUBLIC_AECS_CLIENT_LIB_H_