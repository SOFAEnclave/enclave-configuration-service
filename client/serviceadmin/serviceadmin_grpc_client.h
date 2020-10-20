#ifndef CLIENT_SERVICEADMIN_SERVICEADMIN_GRPC_CLIENT_H_
#define CLIENT_SERVICEADMIN_SERVICEADMIN_GRPC_CLIENT_H_

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "./aecs_service.grpc.pb.h"
#include "./aecs_service.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using tee::DigitalEnvelopeEncrypted;
using tee::EnclaveMatchRules;
using tee::RaReportAuthentication;
using tee::SignatureAuthentication;

using tee::AdminRemoteCallRequest;
using tee::AdminRemoteCallResponse;
using tee::Aecs;
using tee::CreateEnclaveSecretRequest;
using tee::CreateEnclaveSecretResponse;
using tee::DestroyEnclaveSecretRequest;
using tee::DestroyEnclaveSecretResponse;
using tee::ListEnclaveSecretRequest;
using tee::ListEnclaveSecretResponse;

namespace aecs {
namespace client {

constexpr int kTimeoutMs = 10000;
constexpr char kSelfSignedCN[] = "enclave-service";
constexpr char kSequenceFile[] = ".service_admin_sequence";

// Only the enclave service administrator can operate the secrets
// belong to this enclave service.
class ServiceAdminClient {
 public:
  ServiceAdminClient(const std::string& ep,
                     const std::string& ca,
                     const std::string& key,
                     const std::string& cert,
                     const std::string& admin_prvkey,
                     const std::string& admin_passwd,
                     const EnclaveMatchRules& enclave_info);
  ~ServiceAdminClient() {}

  TeeErrorCode GetServerPublicKey(const std::string& service_name);

  // Create one secret for the specified enclave service
  TeeErrorCode CreateEnclaveSecret(const std::string& service_name,
                                   const CreateEnclaveSecretRequest& req,
                                   CreateEnclaveSecretResponse* res);
  // Destroy the enclave service secret by service_name and secret name
  TeeErrorCode DestroyEnclaveSecret(const std::string& service_name,
                                    const DestroyEnclaveSecretRequest& req,
                                    DestroyEnclaveSecretResponse* res);
  // List all the enclave service secrets or only one by specified name
  TeeErrorCode ListEnclaveSecret(const std::string& service_name,
                                 const ListEnclaveSecretRequest& req,
                                 ListEnclaveSecretResponse* res);

 private:
  std::unique_ptr<Aecs::Stub> PrepareSecureStub(const std::string& ep,
                                                const std::string& ca,
                                                const std::string& key,
                                                const std::string& cert);
  bool WaitForChannelReady(std::shared_ptr<Channel> channel,
                           int timeout_ms = kTimeoutMs);

  TeeErrorCode RemoteCall(const std::string& service_name,
                          const std::string& function_name,
                          const google::protobuf::Message& req,
                          google::protobuf::Message* res);
  TeeErrorCode CheckStatusCode(const Status& status, const char* func);

  TeeErrorCode EnvelopeEncryptAndSign(const std::string& service_name,
                                      const std::string& encrypt_pubkey,
                                      const std::string& signing_prvkey,
                                      const std::string& plain,
                                      DigitalEnvelopeEncrypted* env);
  TeeErrorCode EnvelopeDecryptAndVerify(const std::string& decrypt_prvkey,
                                        const std::string& verify_pubkey,
                                        const DigitalEnvelopeEncrypted& env,
                                        std::string* plain);
  TeeErrorCode CheckServerRaReport(const RaReportAuthentication& auth);
  TeeErrorCode AddAdminSignature(const std::string& service_name,
                                 DigitalEnvelopeEncrypted* env);

  std::unique_ptr<Aecs::Stub> stub_;
  const std::string admin_prvkey_;
  const std::string admin_passwd_;
  const tee::EnclaveMatchRules& server_info_;
  std::string server_pubkey_;
};

}  // namespace client
}  // namespace aecs

#endif  // CLIENT_SERVICEADMIN_SERVICEADMIN_GRPC_CLIENT_H_
