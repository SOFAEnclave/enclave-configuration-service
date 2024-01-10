#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "aecs/error.h"
#include "aecsadmin/aecsadmin_grpc_client.h"

namespace aecs {
namespace client {

AecsAdminClient::AecsAdminClient(const kubetee::KubeConfig& conf,
                                 const std::string& admin_passwd) {
  kubetee::common::DataBytes prvkey(conf.identity_key());
  admin_prvkey_ = prvkey.FromBase64().GetStr();
  admin_passwd_ = admin_passwd;
  server_policy_ = conf.server_policy();

  std::string endpoint = conf.server_endpoint();
  if (IsSecureChannel(conf.client_rpc_secure())) {
    kubetee::common::DataBytes client_ca(conf.client_ca());
    kubetee::common::DataBytes client_key(conf.client_key());
    kubetee::common::DataBytes client_cert(conf.client_cert());
    std::string ca = client_ca.FromBase64().GetStr();
    std::string key = client_key.FromBase64().GetStr();
    std::string cert = client_cert.FromBase64().GetStr();
    stub_ = Aecs::NewStub(CreateSecureChannel(endpoint, ca, key, cert));
  } else {
    stub_ = Aecs::NewStub(CreateInsecureChannel(endpoint));
  }
}

TeeErrorCode AecsAdminClient::GetAecsStatus() {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + milliseconds(kAecsAdminClientTimeoutMs));

  kubetee::GetAecsStatusRequest request;
  kubetee::GetAecsStatusResponse response;

  Status status = stub_->GetAecsStatus(&context, request, &response);
  TEE_CHECK_RETURN(CHECK_STATUS(status));
  TEE_CHECK_RETURN(CheckServerRaReport(response.auth_ra_report()));

  // Save server_pubkey_ for later use
  if (!response.auth_ra_report().pem_public_key().empty()) {
    server_pubkey_ = response.auth_ra_report().pem_public_key();
    TEE_LOG_DEBUG("Save AECS server public key\n%s", server_pubkey_.c_str());
  }

  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Verify(server_pubkey_, response.status_str(),
                                   response.status_sig()));
  enclave_status_.assign(response.status_str());

  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::SyncWithRemoteAecs(
    const SyncWithRemoteAecsRequest& req, SyncWithRemoteAecsResponse* res) {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + milliseconds(kAecsAdminClientTimeoutMs));

  // Verify the RA report and remote public key
  Status status = stub_->SyncWithRemoteAecs(&context, req, res);
  TEE_CHECK_RETURN(CHECK_STATUS(status));
  TEE_CHECK_RETURN(CheckServerRaReport(res->auth_ra_report()));

  // Verify the status by remote public key
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Verify(res->auth_ra_report().pem_public_key(),
                                   res->status_str(), res->status_sig()));

  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::RemoteCall(const std::string& function_name,
                                         const google::protobuf::Message& req,
                                         google::protobuf::Message* res) {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + milliseconds(kAecsAdminClientTimeoutMs));

  kubetee::AdminRemoteCallRequest request;
  kubetee::AdminRemoteCallResponse response;

  // Make sure there is AECS server enclave public key to encrypt request
  if (server_pubkey_.empty()) {
    TEE_LOG_ERROR("Invalid AECS server public key");
    return AECS_ERROR_CLIENT_EMPTY_SERVER_PUBLIC_KEY;
  }

  // Combine the serialized original request and password
  std::string req_str;
  PB2JSON(req, &req_str);
  kubetee::AdminRemoteCallReqWithAuth remote_req;
  remote_req.set_req(req_str);
  remote_req.set_password(admin_passwd_);
  std::string remote_req_str;
  PB2JSON(remote_req, &remote_req_str);

  // Prepare the final remote call request, encrypt and sign the function req
  if (!remote_req_str.empty()) {
    TEE_CHECK_RETURN(EnvelopeEncryptAndSign(server_pubkey_, admin_prvkey_,
                                            remote_req_str,
                                            request.mutable_req_enc()));
  }
  request.set_function_name(function_name);

  // Call the remote trusted function
  Status status = stub_->AecsAdminRemoteCall(&context, request, &response);
  TEE_CHECK_RETURN(CHECK_STATUS(status));

  // Verify the AECS server RA report
  TEE_CHECK_RETURN(CheckServerRaReport(response.auth_ra_report()));

  // Decrypt, verify signature and then return the function response
  if (!response.res_enc().aes_cipher().cipher().empty()) {
    std::string res_str;
    TEE_CHECK_RETURN(EnvelopeDecryptAndVerify(admin_prvkey_, server_pubkey_,
                                              response.res_enc(), &res_str));
    JSON2PB(res_str, res);
  }

  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::RegisterEnclaveService(
    const RegisterEnclaveServiceRequest& req,
    RegisterEnclaveServiceResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("RegisterEnclaveService", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::UnregisterEnclaveService(
    const UnregisterEnclaveServiceRequest& req,
    UnregisterEnclaveServiceResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("UnregisterEnclaveService", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::ListEnclaveService(
    const ListEnclaveServiceRequest& req, ListEnclaveServiceResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("ListEnclaveService", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::ListTaSecret(const AecsListTaSecretRequest& req,
                                           AecsListTaSecretResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("ListTaSecret", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::DestroyTaSecret(
    const AecsDestroyTaSecretRequest& req, AecsDestroyTaSecretResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("DestroyTaSecret", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::AecsProvision(const AecsProvisionRequest& req,
                                            AecsProvisionResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("AecsProvision", req, res));
  TEE_CHECK_RETURN(GetAecsStatus());
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::AecsBackupIdentity(
    const AecsBackupIdentityRequest& req, AecsBackupIdentityResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("AecsBackupIdentity", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::AecsListBackupIdentity(
    const AecsListBackupIdentityRequest& req,
    AecsListBackupIdentityResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("AecsListBackupIdentity", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::AecsDeleteBackupIdentity(
    const AecsDeleteBackupIdentityRequest& req,
    AecsDeleteBackupIdentityResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("AecsDeleteBackupIdentity", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::EnvelopeEncryptAndSign(
    const std::string& encrypt_pubkey,
    const std::string& signing_prvkey,
    const std::string& plain,
    kubetee::DigitalEnvelopeEncrypted* env) {
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(envelope.Sign(signing_prvkey, plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::EnvelopeDecryptAndVerify(
    const std::string& decrypt_prvkey,
    const std::string& verify_pubkey,
    const kubetee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(decrypt_prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::CheckServerRaReport(
    const UnifiedAttestationAuthReport& auth) {
  TEE_CHECK_RETURN(UaVerifyAuthReport(auth, server_policy_));
  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
