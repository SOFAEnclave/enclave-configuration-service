#ifndef INCLUDE_AECS_UNTRUSTED_CONFIG_H_
#define INCLUDE_AECS_UNTRUSTED_CONFIG_H_

#include <string>

#include "unified_attestation/ua_untrusted.h"

constexpr char kAecsConfFile[] = "aecs_server.json";

constexpr char kAecsConfReportCache[] = "aecs_attestation_report_cache";
constexpr char kAecsConfReportCacheFile[] = "aecs_attestation_report_file";
constexpr char kAecsConfIdentityKeyCache[] = "aecs_identity_keypair_cache";
constexpr char kAecsConfIdentityKeyCacheFile[] = "aecs_identity_keypair_file";
constexpr char kAecsConfRpcRemoteServer[] = "aecs_rpc_remote_server";
constexpr char kAecsConfRpcRemotePort[] = "aecs_rpc_remote_port";
constexpr char kAecsConfRpcServer[] = "aecs_rpc_server";
constexpr char kAecsConfRpcPort[] = "aecs_rpc_port";
constexpr char kAecsConfRpcSslSecure[] = "aecs_rpc_ssl_secure";
constexpr char kAecsConfRpcSslCa[] = "aecs_rpc_ca_path";
constexpr char kAecsConfRpcSslCert[] = "aecs_rpc_cert_path";
constexpr char kAecsConfRpcSslKey[] = "aecs_rpc_key_path";

constexpr char kAecsConfBackendLib[] = "aecs_storage_backend_lib";
constexpr char kAecsConfAdminPubKey[] = "aecs_admin_pubkey";
constexpr char kAecsConfAdminPasswordHash[] = "aecs_admin_password_hash";
constexpr char kAecsConfServerEnclave[] = "aecs_server_enclave";

constexpr char kAecsEnvRpcRemoteServer[] = "AECS_ROOT_SERVER";
constexpr char kAecsEnvRpcRemotePort[] = "AECS_ROOT_PORT";
constexpr char kAecsEnvRpcPort[] = "AECS_RPC_PORT";
constexpr char kAecsEnvStorageLib[] = "AECS_STORAGE_BACKEND_LIB";
constexpr char kAecsEnvAdminPwHash[] = "AECS_ADMIN_PASSWORD_HASH";

#define AECS_CONF_STR(name) JSON_CONF_STR(kAecsConfFile, (name))
#define AECS_CONF_FILE_STR(name) GetConfFileStr(kAecsConfFile, (name))
#define AECS_ENV_CONF_STR(en, cn) GetEnvConfStr(kAecsConfFile, (en), (cn))

#endif  // INCLUDE_AECS_UNTRUSTED_CONFIG_H_
