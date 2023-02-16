#ifndef SERVER_UNTRUSTED_UNTRUSTED_FUNCTION_STORAGE_H_
#define SERVER_UNTRUSTED_UNTRUSTED_FUNCTION_STORAGE_H_

#include <string>

#include "unified_attestation/ua_untrusted.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode ReeStorageCreate(const std::string& req_str, std::string* res_str);
TeeErrorCode ReeStorageDelete(const std::string& req_str, std::string* res_str);
TeeErrorCode ReeStorageGetValue(const std::string& req_str,
                                std::string* res_str);
TeeErrorCode ReeStorageListAll(const std::string& req_str,
                               std::string* res_str);
TeeErrorCode ReeStorageCheckExist(const std::string& req_str,
                                  std::string* res_str);

#ifdef __cplusplus
}
#endif

#endif  // SERVER_UNTRUSTED_UNTRUSTED_FUNCTION_STORAGE_H_
