#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "aecs/error.h"
#include "serviceadmin/serviceadmin_grpc_client.h"

namespace aecs {
namespace client {

ServiceAdminClient::ServiceAdminClient(const kubetee::KubeConfig& conf,
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

TeeErrorCode ServiceAdminClient::GetAecsStatus() {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + milliseconds(kServiceAdminClientTimeoutMs));

  kubetee::GetAecsStatusRequest request;
  kubetee::GetAecsStatusResponse response;

  Status status = stub_->GetAecsStatus(&context, request, &response);
  TEE_CHECK_RETURN(CHECK_STATUS(status));
  TEE_CHECK_RETURN(CheckServerRaReport(response.auth_ra_report()));

  // If the server_pubkey_ is not saved, save it for later use
  // It should only be saved when GetAecsStatus is called first time
  if (server_pubkey_.empty()) {
    TEE_LOG_DEBUG("Save AECS server public key\n%s", server_pubkey_.c_str());
    server_pubkey_ = response.auth_ra_report().pem_public_key();
  }

  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Verify(server_pubkey_, response.status_str(),
                                   response.status_sig()));
  TEE_LOG_DEBUG("AECS server status: %s", response.status_str().c_str());

  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::RemoteCall(
    const std::string& service_name,
    const std::string& function_name,
    const google::protobuf::Message& req,
    google::protobuf::Message* res) {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + milliseconds(kServiceAdminClientTimeoutMs));

  kubetee::AdminRemoteCallRequest request;
  kubetee::AdminRemoteCallResponse response;

  if (server_pubkey_.empty()) {
    TEE_LOG_ERROR("Invalid AECS server public key");
    return AECS_ERROR_CLIENT_EMPTY_SERVER_PUBLIC_KEY;
  }

  // Serialize the original request, encrypt and sign it
  std::string req_str;
  PB2JSON(req, &req_str);
  kubetee::AdminRemoteCallReqWithAuth remote_req;
  remote_req.set_req(req_str);
  remote_req.set_password(admin_passwd_);

  // Get the final remote call request string
  std::string remote_req_str;
  PB2JSON(remote_req, &remote_req_str);

  request.set_function_name(function_name);
  TEE_CHECK_RETURN(EnvelopeEncryptAndSign(service_name, server_pubkey_,
                                          admin_prvkey_, remote_req_str,
                                          request.mutable_req_enc()));

  // Call the remote trusted function
  Status status = stub_->ServiceAdminRemoteCall(&context, request, &response);
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

TeeErrorCode ServiceAdminClient::CreateEnclaveSecret(
    const std::string& service_name,
    const CreateEnclaveSecretRequest& req,
    CreateEnclaveSecretResponse* res) {
  TEE_CHECK_RETURN(RemoteCall(service_name, "CreateSecret", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::DestroyEnclaveSecret(
    const std::string& service_name,
    const DestroyEnclaveSecretRequest& req,
    DestroyEnclaveSecretResponse* res) {
  TEE_CHECK_RETURN(RemoteCall(service_name, "DestroySecret", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::ListEnclaveSecret(
    const std::string& service_name,
    const ListEnclaveSecretRequest& req,
    ListEnclaveSecretResponse* res) {
  TEE_CHECK_RETURN(RemoteCall(service_name, "ListSecret", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::GetEnclaveSecretPublic(
    const GetEnclaveSecretPublicRequest& req,
    GetEnclaveSecretPublicResponse* res) {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + milliseconds(kServiceAdminClientTimeoutMs));

  // Call the remote trusted function
  Status status = stub_->GetEnclaveSecretPublic(&context, req, res);
  TEE_CHECK_RETURN(CHECK_STATUS(status));

  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::EnvelopeEncryptAndSign(
    const std::string& service_name,
    const std::string& encrypt_pubkey,
    const std::string& signing_prvkey,
    const std::string& plain,
    kubetee::DigitalEnvelopeEncrypted* env) {
  kubetee::common::DigitalEnvelope envelope(service_name);
  TEE_CHECK_RETURN(envelope.Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(envelope.Sign(signing_prvkey, plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::EnvelopeDecryptAndVerify(
    const std::string& decrypt_prvkey,
    const std::string& verify_pubkey,
    const kubetee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  kubetee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(decrypt_prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::CheckServerRaReport(
    const UnifiedAttestationAuthReport& auth) {
  TEE_CHECK_RETURN(UaVerifyAuthReport(auth, server_policy_));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::AddAdminSignature(
    const std::string& service_name, DigitalEnvelopeEncrypted* env) {
  // Place the service name into aes_ciphre AAD field
  env->mutable_aes_cipher()->set_aad(service_name);

  // Calculate the service name hash and sign it
  kubetee::common::DataBytes service_name_hash(service_name);
  std::string* signature = env->mutable_plain_hash_sig();
  kubetee::common::RsaCrypto rsa;
  TEE_CHECK_RETURN(rsa.Sign(admin_prvkey_,
                            service_name_hash.ToSHA256().GetStr(), signature));

  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
