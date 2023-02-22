#ifndef OCCLUM_AECS_CLIENT_LIB_H_
#define OCCLUM_AECS_CLIENT_LIB_H_

#include <string>
#include "attestation/common/error.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode aecs_client_get_secret_to_file(
    const std::string& aecs_server_endpoint,
    const std::string& aecs_server_policy,
    const std::string& secret_service,
    const std::string& secret_name,
    const std::string& save_file_name);

/**
 * @brief Get Secret for TEE application
 *
 * @param[in] aecs_server_endpoint
 * @param[in] secret_service
 * @param[in] secret_name
 * @param[out] secret Json-format secret
 * @return int Error code
 */
TeeErrorCode aecs_client_get_secret(const std::string& aecs_server_endpoint,
                                    const std::string& aecs_server_policy,
                                    const std::string& secret_service,
                                    const std::string& secret_name,
                                    std::string* secret);

#ifdef __cplusplus
}
#endif

#endif  // OCCLUM_AECS_CLIENT_LIB_H_
