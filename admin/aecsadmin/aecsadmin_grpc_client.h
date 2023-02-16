#ifndef ADMIN_AECSADMIN_AECSADMIN_GRPC_CLIENT_H_
#define ADMIN_AECSADMIN_AECSADMIN_GRPC_CLIENT_H_

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

using kubetee::Aecs;

using kubetee::GetAecsStatusRequest;
using kubetee::GetAecsStatusResponse;

using kubetee::SyncWithRemoteAecsRequest;
using kubetee::SyncWithRemoteAecsResponse;

using kubetee::AdminRemoteCallRequest;
using kubetee::AdminRemoteCallResponse;

using kubetee::AecsBackupIdentityRequest;
using kubetee::AecsBackupIdentityResponse;
using kubetee::AecsDeleteBackupIdentityRequest;
using kubetee::AecsDeleteBackupIdentityResponse;
using kubetee::AecsListBackupIdentityRequest;
using kubetee::AecsListBackupIdentityResponse;

using kubetee::AecsProvisionRequest;
using kubetee::AecsProvisionResponse;
using kubetee::ListEnclaveServiceRequest;
using kubetee::ListEnclaveServiceResponse;
using kubetee::RegisterEnclaveServiceRequest;
using kubetee::RegisterEnclaveServiceResponse;
using kubetee::UnregisterEnclaveServiceRequest;
using kubetee::UnregisterEnclaveServiceResponse;

using std::chrono::milliseconds;

namespace aecs {
namespace client {

constexpr int kAecsAdminClientTimeoutMs = 10000;

class AecsAdminClient : public kubetee::untrusted::TeeGrpcClient {
 public:
  AecsAdminClient(const kubetee::KubeConfig& conf,
                  const std::string& admin_passwd);
  ~AecsAdminClient() {}

  // Get AECS server status
  TeeErrorCode GetAecsStatus();

  // Sync the provision secret from remote AECS instance
  TeeErrorCode SyncWithRemoteAecs(const SyncWithRemoteAecsRequest& req,
                                  SyncWithRemoteAecsResponse* res);

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
  // Backup the enclave identity key in one aecs instance
  TeeErrorCode AecsBackupIdentity(const AecsBackupIdentityRequest& req,
                                  AecsBackupIdentityResponse* res);
  // List all or special backup of the enclave identity key
  TeeErrorCode AecsListBackupIdentity(const AecsListBackupIdentityRequest& req,
                                      AecsListBackupIdentityResponse* res);
  // Delete identity key backup by name
  TeeErrorCode AecsDeleteBackupIdentity(
      const AecsDeleteBackupIdentityRequest& req,
      AecsDeleteBackupIdentityResponse* res);

  // Get the cached status
  const std::string& CachedStatus() {
    return enclave_status_;
  }

 private:
  TeeErrorCode RemoteCall(const std::string& function_name,
                          const google::protobuf::Message& req,
                          google::protobuf::Message* res);

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
  TeeErrorCode CheckServerRaReport(const UnifiedAttestationAuthReport& auth);

  std::unique_ptr<Aecs::Stub> stub_;
  std::string admin_prvkey_;
  std::string admin_passwd_;
  kubetee::UnifiedAttestationPolicy server_policy_;
  std::string server_pubkey_;
  std::string enclave_status_;
};

}  // namespace client
}  // namespace aecs

#endif  // ADMIN_AECSADMIN_AECSADMIN_GRPC_CLIENT_H_
