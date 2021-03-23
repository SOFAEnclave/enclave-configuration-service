#ifndef SERVER_UNTRUSTED_UNTRUSTED_AECS_SERVER_H_
#define SERVER_UNTRUSTED_UNTRUSTED_AECS_SERVER_H_

#include <string>

#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "grpcpp/grpcpp.h"

#include "tee/common/error.h"
#include "tee/common/type.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "./aecs_service.grpc.pb.h"
#include "./aecs_service.pb.h"

constexpr char kIdentityName[] = "EnclaveIdentity";

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCredentials;
using grpc::SslServerCredentials;
using grpc::SslServerCredentialsOptions;
using grpc::Status;

using tee::DigitalEnvelopeEncrypted;
using tee::EnclaveInformation;
using tee::EnclaveMatchRules;
using tee::EnclaveSecretPolicy;
using tee::IasReport;
using tee::PbGenericRequest;
using tee::PbGenericResponse;
using tee::RaReportAuthentication;
using tee::SymmetricKeyEncrypted;

using tee::Aecs;

using tee::GetRemoteSecretRequest;
using tee::GetRemoteSecretResponse;

using tee::CreateEnclaveSecretRequest;
using tee::CreateEnclaveSecretResponse;
using tee::DestroyEnclaveSecretRequest;
using tee::DestroyEnclaveSecretResponse;
using tee::GetEnclaveSecretRequest;
using tee::GetEnclaveSecretResponse;
using tee::GetIdentityPublicKeyRequest;
using tee::GetIdentityPublicKeyResponse;
using tee::ListEnclaveSecretRequest;
using tee::ListEnclaveSecretResponse;

using tee::AdminRemoteCallRequest;
using tee::AdminRemoteCallResponse;
using tee::ListEnclaveServiceRequest;
using tee::ListEnclaveServiceResponse;
using tee::RegisterEnclaveServiceRequest;
using tee::RegisterEnclaveServiceResponse;

#define RETURN_ERROR(msg)                           \
  do {                                              \
    TEE_LOG_ERROR(msg);                             \
    return Status(grpc::StatusCode::INTERNAL, msg); \
  } while (0)

#define GRPC_INTERFACE_ENTER_DEBUG() \
  TEE_LOG_DEBUG("GRPC SERVER INTERFACE:%s", __FUNCTION__)

namespace aecs {
namespace untrusted {

class AecsServiceImpl final : public Aecs::Service {
 public:
  // For AECS enclaves
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

  TeeErrorCode InitializeServerImpl(EnclaveInstance* enclave);
  TeeErrorCode CheckRaAuthentication(const RaReportAuthentication& auth);
  TeeErrorCode GetServerRaAuthentication(RaReportAuthentication* auth);

 private:
  TeeErrorCode VerifySignatureAuth(const std::string& data,
                                   const std::string& signature);
  TeeErrorCode CheckMatchRules(const RaReportAuthentication& auth,
                               const EnclaveMatchRules& match_rules);
  TeeErrorCode GetMatchRulesFromRaReport(const RaReportAuthentication& auth,
                                         EnclaveMatchRules* rule);
  Status GetEnclaveSecret_(const std::string& secret_name,
                           const RaReportAuthentication& auth,
                           DigitalEnvelopeEncrypted* keys_enc);

  EnclaveInstance* enclave_;
  IasReport server_ias_report_;
};

class AecsServer {
 public:
  AecsServer();

  TeeErrorCode InitServer(EnclaveInstance* enclave);
  TeeErrorCode RunServer();

 private:
  TeeErrorCode SyncIdentityKeysFromRemote();

  AecsServiceImpl service_impl_;
  EnclaveInstance* enclave_;
  std::string root_server_;
  std::string root_port_;
  std::string rpc_port_;
  std::string ssl_cert_;
  std::string ssl_key_;
  std::string ssl_ca_;
};

}  // namespace untrusted
}  // namespace aecs

#endif  // SERVER_UNTRUSTED_UNTRUSTED_AECS_SERVER_H_
