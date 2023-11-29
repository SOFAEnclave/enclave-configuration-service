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
 * @param[in] aecs_server_policy
 * @param[in] secret_service
 * @param[in] secret_name
 * @param[in] secret_policy
 * @param[in] hex_user_data to generate special client auth report
 * @param[in] nonce freshness for this request
 * @param[in] save_file_name name to save secret
 * @return int Error code
 */
int aecs_client_get_secret_file(const char* aecs_server_endpoint,
                                const char* aecs_server_policy,
                                const char* secret_service,
                                const char* secret_name,
                                const char* secret_policy,
                                const char* hex_user_data,
                                const char* nonce,
                                const char* save_file_name);

// This function is deprecated, please use the new version above
int aecs_client_get_secret_and_save_file(const char* aecs_server_endpoint,
                                         const char* aecs_server_policy,
                                         const char* secret_service,
                                         const char* secret_name,
                                         const char* nonce,
                                         const char* save_file_name);

/**
 * @brief Get Secret for TEE application and return it buffer
 *
 * @param[in] aecs_server_endpoint
 * @param[in] aecs_server_policy
 * @param[in] secret_service
 * @param[in] secret_name
 * @param[in] secret_policy
 * @param[in] hex_user_data to generate special client auth report
 * @param[in] nonce freshness for this request
 * @param[out] secret_outbuf output buffer which includes the secret
 * @param[inout] secret_outbuf_len max len as input/real len as output
 * @return int Error code
 */
int aecs_client_get_secret_buffer(const char* aecs_server_endpoint,
                                  const char* aecs_server_policy,
                                  const char* secret_service,
                                  const char* secret_name,
                                  const char* secret_policy,
                                  const char* hex_user_data,
                                  const char* nonce,
                                  char* secret_outbuf,
                                  int* secret_outbuf_len);

// This function is deprecated, please use the new version above
int aecs_client_get_secret_by_buffer(const char* aecs_server_endpoint,
                                     const char* aecs_server_policy,
                                     const char* secret_service,
                                     const char* secret_name,
                                     const char* nonce,
                                     char* secret_outbuf,
                                     int* secret_outbuf_len);

/**
 * @brief Create Trusted application bound secret
 *
 * @details Trusted application bound secret means the secret can only
 *          be used and delete by the trusted application which create it.
 *
 * @param[in] aecs_server_endpoint
 * @param[in] aecs_server_policy
 * @param[in] secret_policy_file defined how to create the secret
 * @param[in] hex_user_data to generate special client auth report
 * @param[in] nonce freshness for this request
 * @return int Error code
 */
int aecs_client_create_ta_secret(const char* aecs_server_endpoint,
                                 const char* aecs_server_policy,
                                 const char* secret_policy_file,
                                 const char* hex_user_data,
                                 const char* nonce);

/**
 * @brief Destroy Trusted application bound secret
 *
 * @param[in] aecs_server_endpoint
 * @param[in] aecs_server_policy
 * @param[in] secret_name
 * @param[in] hex_user_data to generate special client auth report
 * @param[in] nonce freshness for this request
 * @return int Error code
 */
int aecs_client_destroy_ta_secret(const char* aecs_server_endpoint,
                                  const char* aecs_server_policy,
                                  const char* secret_name,
                                  const char* hex_user_data,
                                  const char* nonce);
#ifdef __cplusplus
}
#endif

#endif  // OCCLUM_AECS_CLIENT_LIB_C_H_
