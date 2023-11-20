#ifndef SERVER_UNTRUSTED_UNTRUSTED_AECS_SERVER_H_
#define SERVER_UNTRUSTED_UNTRUSTED_AECS_SERVER_H_

#include <string>

#include "./sgx_quote.h"
#include "./sgx_report.h"
#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "unified_attestation/ua_untrusted.h"

#include "grpcpp/grpcpp.h"

#include "./aecs_service.grpc.pb.h"
#include "./aecs_service.pb.h"

using grpc::Server;
using grpc::Status;

using kubetee::DigitalEnvelopeEncrypted;
using kubetee::UnifiedAttestationAuthReport;
using kubetee::UnifiedAttestationNestedPolicy;

using kubetee::AdminRemoteCallRequest;
using kubetee::AdminRemoteCallResponse;
using kubetee::CreateTaSecretRequest;
using kubetee::CreateTaSecretResponse;
using kubetee::DestroyTaSecretRequest;
using kubetee::DestroyTaSecretResponse;
using kubetee::GetAecsStatusRequest;
using kubetee::GetAecsStatusResponse;
using kubetee::GetEnclaveSecretPublicRequest;
using kubetee::GetEnclaveSecretPublicResponse;
using kubetee::GetEnclaveSecretRequest;
using kubetee::GetEnclaveSecretResponse;
using kubetee::GetRemoteSecretRequest;
using kubetee::GetRemoteSecretResponse;
using kubetee::SyncWithRemoteAecsRequest;
using kubetee::SyncWithRemoteAecsResponse;

#define RETURN_ERROR(err, msg)                                              \
  if ((err) != TEE_SUCCESS) {                                               \
    constexpr size_t kMaxMsgBufSize = 4096;                                 \
    char buf[kMaxMsgBufSize] = {'\0'};                                      \
    snprintf(buf, kMaxMsgBufSize, "%s | Error code: 0x%08X", (msg), (err)); \
    TEE_LOG_ERROR("%s", buf);                                               \
    return Status(grpc::StatusCode::INTERNAL, buf);                         \
  }

#define GRPC_INTERFACE_ENTER_DEBUG() \
  TEE_LOG_DEBUG("GRPC SERVER INTERFACE ENTER:%s", __FUNCTION__)
#define GRPC_INTERFACE_EXIT_DEBUG() \
  TEE_LOG_DEBUG("GRPC SERVER INTERFACE EXIT:%s", __FUNCTION__)

namespace aecs {
namespace untrusted {

class AecsServiceImpl final : public kubetee::Aecs::Service {
 public:
  // For AECS enclaves
  Status GetAecsStatus(ServerContext* context,
                       const GetAecsStatusRequest* req,
                       GetAecsStatusResponse* res);

  Status SyncWithRemoteAecs(ServerContext* context,
                            const SyncWithRemoteAecsRequest* req,
                            SyncWithRemoteAecsResponse* res);

  Status GetRemoteSecret(ServerContext* context,
                         const GetRemoteSecretRequest* req,
                         GetRemoteSecretResponse* res);

  // The interfaces wrapper for AECS and service administrator
  Status AecsAdminRemoteCall(ServerContext* context,
                             const AdminRemoteCallRequest* req,
                             AdminRemoteCallResponse* res);
  Status ServiceAdminRemoteCall(ServerContext* context,
                                const AdminRemoteCallRequest* req,
                                AdminRemoteCallResponse* res);

  // For enclave services
  Status GetEnclaveSecret(ServerContext* context,
                          const GetEnclaveSecretRequest* req,
                          GetEnclaveSecretResponse* res);

  // For non tee client and all
  Status GetEnclaveSecretPublic(ServerContext* context,
                                const GetEnclaveSecretPublicRequest* req,
                                GetEnclaveSecretPublicResponse* res);

  // For creating trusted application bound secret
  Status CreateTaSecret(ServerContext* context,
                        const CreateTaSecretRequest* req,
                        CreateTaSecretResponse* res);

  // For deleting trusted application bound secret
  Status DestroyTaSecret(ServerContext* context,
                         const DestroyTaSecretRequest* req,
                         DestroyTaSecretResponse* res);

  TeeErrorCode InitializeServerImpl(EnclaveInstance* enclave);
  TeeErrorCode CheckRaAuthentication(const UnifiedAttestationAuthReport& auth);
  TeeErrorCode GetServerRaAuthentication(UnifiedAttestationAuthReport* auth);
  TeeErrorCode AecsSyncFromRemote(const std::string& remote_endpoint);

 private:
  TeeErrorCode VerifySignatureAuth(const std::string& data,
                                   const std::string& signature);
  TeeErrorCode CheckMatchRules(
      const UnifiedAttestationAuthReport& auth,
      const UnifiedAttestationNestedPolicy& match_rules);
  TeeErrorCode GetMatchRulesFromRaReport(
      const UnifiedAttestationAuthReport& auth,
      UnifiedAttestationNestedPolicy* rule);
  Status GetEnclaveSecret_(const std::string& secret_name,
                           const UnifiedAttestationAuthReport& auth,
                           DigitalEnvelopeEncrypted* keys_enc);

  EnclaveInstance* enclave_;
};

class AecsServer : public kubetee::untrusted::TeeGrpcServer {
 public:
  TeeErrorCode InitServer(EnclaveInstance* enclave);
  TeeErrorCode RunServer();

 private:
  TeeErrorCode SyncIdentityKeysFromRemote();

  AecsServiceImpl service_impl_;
  EnclaveInstance* enclave_;
  std::string root_server_;
  std::string root_port_;
  std::string rpc_port_;
  std::string ssl_secure_;
  std::string ssl_cert_;
  std::string ssl_key_;
  std::string ssl_ca_;
};

}  // namespace untrusted
}  // namespace aecs

#endif  // SERVER_UNTRUSTED_UNTRUSTED_AECS_SERVER_H_
