#ifndef CLIENT_AECSADMIN_AECSADMIN_GRPC_CLIENT_H_
#define CLIENT_AECSADMIN_AECSADMIN_GRPC_CLIENT_H_

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
using tee::RaReportAuthentication;
using tee::SignatureAuthentication;

using tee::AdminRemoteCallRequest;
using tee::AdminRemoteCallResponse;
using tee::Aecs;
using tee::AecsProvisionRequest;
using tee::AecsProvisionResponse;
using tee::ListEnclaveServiceRequest;
using tee::ListEnclaveServiceResponse;
using tee::RegisterEnclaveServiceRequest;
using tee::RegisterEnclaveServiceResponse;
using tee::UnregisterEnclaveServiceRequest;
using tee::UnregisterEnclaveServiceResponse;

namespace aecs {
namespace client {

constexpr int kTimeoutMs = 10000;
constexpr char kSelfSignedCN[] = "enclave-service";
constexpr char kSequenceFile[] = ".aecs_admin_sequence";

class AecsAdminClient {
 public:
  AecsAdminClient(const std::string& ep,
                  const std::string& ca,
                  const std::string& key,
                  const std::string& cert,
                  const std::string& admin_prvkey,
                  const std::string& admin_passwd,
                  const tee::EnclaveMatchRules& enclave_info);
  ~AecsAdminClient() {}

  TeeErrorCode GetServerPublicKey();

  // Register the enclave service and its public key for later authentication
  TeeErrorCode RegisterEnclaveService(const RegisterEnclaveServiceRequest& req,
                                      RegisterEnclaveServiceResponse* res);
  // Unregister the enclave service and remove all related secrets
  TeeErrorCode UnregisterEnclaveService(
      const UnregisterEnclaveServiceRequest& req,
      UnregisterEnclaveServiceResponse* res);
  // Listed all the registered services
  TeeErrorCode ListEnclaveService(const ListEnclaveServiceRequest& req,
                                  ListEnclaveServiceResponse* res);
  // Provision the AECS administrator public key,
  // optional storage authentication, and so on.
  // All these secrets should be set only once.
  TeeErrorCode AecsProvision(const AecsProvisionRequest& req,
                             AecsProvisionResponse* res);

 private:
  std::unique_ptr<Aecs::Stub> PrepareSecureStub(const std::string& ep,
                                                const std::string& ca,
                                                const std::string& key,
                                                const std::string& cert);
  bool WaitForChannelReady(std::shared_ptr<Channel> channel,
                           int timeout_ms = kTimeoutMs);

  TeeErrorCode RemoteCall(const std::string& function_name,
                          const google::protobuf::Message& req,
                          google::protobuf::Message* res);
  TeeErrorCode CheckStatusCode(const Status& status, const char* func);

  // Encrypt the administrator request and sign it the admin private key
  TeeErrorCode EnvelopeEncryptAndSign(const std::string& encrypt_pubkey,
                                      const std::string& signing_prvkey,
                                      const std::string& plain,
                                      DigitalEnvelopeEncrypted* env);
  // Decrypt the administrator response and verify the remote signature
  TeeErrorCode EnvelopeDecryptAndVerify(const std::string& decrypt_prvkey,
                                        const std::string& verify_pubkey,
                                        const DigitalEnvelopeEncrypted& env,
                                        std::string* plain);
  TeeErrorCode CheckServerRaReport(const RaReportAuthentication& auth);
  TeeErrorCode AddAdminSignature(DigitalEnvelopeEncrypted* env);

  std::unique_ptr<Aecs::Stub> stub_;
  const std::string admin_prvkey_;
  const std::string admin_passwd_;
  const tee::EnclaveMatchRules& server_info_;
  std::string server_pubkey_;
};

}  // namespace client
}  // namespace aecs

#endif  // CLIENT_AECSADMIN_AECSADMIN_GRPC_CLIENT_H_
