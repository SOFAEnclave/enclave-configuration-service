#ifndef PUBLIC_AECS_CLIENT_LIB_C_H_
#define PUBLIC_AECS_CLIENT_LIB_C_H_

#include <cstdio>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Get secret public key for TEE application and Save to file
 *
 * @param[in] aecs_server_endpoint
 * @param[in] aecs_server_policy
 * @param[in] secret_service
 * @param[in] secret_name
 * @param[in] secret_policy
 * @param[in] nonce
 * @param[in] file name to save secret public key
 * @return int Error code
 */
int aecs_client_get_secret_public_file(const char* aecs_server_endpoint,
                                       const char* aecs_server_policy,
                                       const char* secret_service,
                                       const char* secret_name,
                                       const char* secret_policy,
                                       const char* nonce,
                                       const char* save_file_name);

int aecs_client_get_public_secret_and_save_file(
    const char* aecs_server_endpoint,
    const char* aecs_server_policy,
    const char* secret_service,
    const char* secret_name,
    const char* nonce,
    const char* save_file_name);

/**
 * @brief Get secret public key for TEE application and return it buffer
 *
 * @param[in] aecs_server_endpoint
 * @param[in] aecs_server_policy
 * @param[in] secret_service
 * @param[in] secret_name
 * @param[in] secret_policy
 * @param[in] nonce
 * @param[out] secret_outbuf output buffer which includes the secret public key
 * @param[inout] secret_outbuf_len max len as input/real len as output
 * @return int Error code
 */
int aecs_client_get_secret_public_buffer(const char* aecs_server_endpoint,
                                         const char* aecs_server_policy,
                                         const char* secret_service,
                                         const char* secret_name,
                                         const char* secret_policy,
                                         const char* nonce,
                                         const char* secret_outbuf,
                                         int* secret_outbuf_len);

int aecs_client_get_public_secret_by_buffer(const char* aecs_server_endpoint,
                                            const char* aecs_server_policy,
                                            const char* secret_service,
                                            const char* secret_name,
                                            const char* secret_policy,
                                            const char* nonce,
                                            const char* secret_outbuf,
                                            int* secret_outbuf_len);

#ifdef __cplusplus
}
#endif

#endif  // PUBLIC_AECS_CLIENT_LIB_C_H_
