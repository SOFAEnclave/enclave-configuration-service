#ifndef OCCLUM_AECS_CLIENT_LIB_C_H_
#define OCCLUM_AECS_CLIENT_LIB_C_H_

#include <cstdio>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Get Secret for TEE application and Save to file
 *
 * @param[in] aecs_server_endpoint
 * @param[in] secret_service
 * @param[in] secret_name
 * @param[in] file name to save secret
 * @return int Error code
 */
int aecs_client_get_secret_and_save_file(const char* aecs_server_endpoint,
                                         const char* aecs_server_policy,
                                         const char* secret_service,
                                         const char* secret_name,
                                         const char* save_file_name);

/**
 * @brief Get Secret for TEE application and return it buffer
 *
 * @param[in] aecs_server_endpoint
 * @param[in] secret_service
 * @param[in] secret_name
 * @param[out] secret_outbuf output buffer which includes the secret
 * @param[inout] secret_outbuf_len max len as input/real len as output
 * @return int Error code
 */
int aecs_client_get_secret_by_buffer(const char* aecs_server_endpoint,
                                     const char* aecs_server_policy,
                                     const char* secret_service,
                                     const char* secret_name,
                                     char* secret_outbuf,
                                     int* secret_outbuf_len);

#ifdef __cplusplus
}
#endif

#endif  // OCCLUM_AECS_CLIENT_LIB_C_H_
