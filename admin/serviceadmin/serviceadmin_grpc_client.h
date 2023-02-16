#ifndef ADMIN_SERVICEADMIN_SERVICEADMIN_GRPC_CLIENT_H_
#define ADMIN_SERVICEADMIN_SERVICEADMIN_GRPC_CLIENT_H_

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "./aecs_admin.pb.h"
#include "./aecs_service.grpc.pb.h"
#include "./aecs_service.pb.h"

using grpc::ClientContext;
using grpc::Status;

using kubetee::DigitalEnvelopeEncrypted;
using kubetee::SignatureAuthentication;
using kubetee::UnifiedAttestationAuthReport;
using kubetee::UnifiedAttestationNestedPolicy;

using kubetee::AdminRemoteCallRequest;
using kubetee::AdminRemoteCallResponse;
using kubetee::Aecs;
using kubetee::CreateEnclaveSecretRequest;
using kubetee::CreateEnclaveSecretResponse;
using kubetee::DestroyEnclaveSecretRequest;
using kubetee::DestroyEnclaveSecretResponse;
using kubetee::GetEnclaveSecretPublicRequest;
using kubetee::GetEnclaveSecretPublicResponse;
using kubetee::ListEnclaveSecretRequest;
using kubetee::ListEnclaveSecretResponse;

using std::chrono::milliseconds;

namespace aecs {
namespace client {

constexpr int kServiceAdminClientTimeoutMs = 10000;

// Only the enclave service administrator can operate the secrets
// belong to this enclave service.
class ServiceAdminClient : public kubetee::untrusted::TeeGrpcClient {
 public:
  ServiceAdminClient(const kubetee::KubeConfig& conf,
                     const std::string& admin_passwd);
  ~ServiceAdminClient() {}

  TeeErrorCode GetAecsStatus();

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
  // Get the enclave service secret public key by name
  // Only works if the type is RSA_KEYPAIR or CERTIFICATE
  // This function is not by Service RemoteCall, we just test it here
  TeeErrorCode GetEnclaveSecretPublic(const GetEnclaveSecretPublicRequest& req,
                                      GetEnclaveSecretPublicResponse* res);

 private:
  TeeErrorCode RemoteCall(const std::string& service_name,
                          const std::string& function_name,
                          const google::protobuf::Message& req,
                          google::protobuf::Message* res);

  TeeErrorCode EnvelopeEncryptAndSign(const std::string& service_name,
                                      const std::string& encrypt_pubkey,
                                      const std::string& signing_prvkey,
                                      const std::string& plain,
                                      DigitalEnvelopeEncrypted* env);
  TeeErrorCode EnvelopeDecryptAndVerify(const std::string& decrypt_prvkey,
                                        const std::string& verify_pubkey,
                                        const DigitalEnvelopeEncrypted& env,
                                        std::string* plain);
  TeeErrorCode CheckServerRaReport(const UnifiedAttestationAuthReport& auth);
  TeeErrorCode AddAdminSignature(const std::string& service_name,
                                 DigitalEnvelopeEncrypted* env);

  std::unique_ptr<Aecs::Stub> stub_;
  std::string admin_prvkey_;
  std::string admin_passwd_;
  kubetee::UnifiedAttestationPolicy server_policy_;
  std::string server_pubkey_;
};

}  // namespace client
}  // namespace aecs

#endif  // ADMIN_SERVICEADMIN_SERVICEADMIN_GRPC_CLIENT_H_
