#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "tee/common/envelope.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/protobuf.h"
#include "tee/common/type.h"
#include "tee/untrusted/ra/untrusted_challenger.h"

#include "serviceadmin/serviceadmin_grpc_client.h"

namespace aecs {
namespace client {

ServiceAdminClient::ServiceAdminClient(const std::string& ep,
                                       const std::string& ca,
                                       const std::string& key,
                                       const std::string& cert,
                                       const std::string& admin_prvkey,
                                       const EnclaveMatchRules& enclave_info)
    : admin_prvkey_(admin_prvkey), server_info_(enclave_info) {
  stub_ = PrepareSecureStub(ep, ca, key, cert);
}

bool ServiceAdminClient::WaitForChannelReady(
    std::shared_ptr<grpc::Channel> channel, int timeout_ms) {
  using std::chrono::system_clock;
  grpc_connectivity_state state;
  while ((state = channel->GetState(true)) != GRPC_CHANNEL_READY) {
    system_clock::time_point now = system_clock::now();
    system_clock::time_point end = now + std::chrono::milliseconds(kTimeoutMs);
    if (!channel->WaitForStateChange(state, end)) {
      return false;
    }
  }
  return true;
}

std::unique_ptr<Aecs::Stub> ServiceAdminClient::PrepareSecureStub(
    const std::string& ep,
    const std::string& ca,
    const std::string& key,
    const std::string& cert) {
  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = ca;
  ssl_opts.pem_private_key = key;
  ssl_opts.pem_cert_chain = cert;

  auto ssl_creds = grpc::SslCredentials(ssl_opts);
  auto channel_args = grpc::ChannelArguments();

  // For certificates CN validation
  channel_args.SetSslTargetNameOverride(kSelfSignedCN);

  // Return a channel using the credentials created in the previous step.
  auto channel = grpc::CreateCustomChannel(ep, ssl_creds, channel_args);

  if (!WaitForChannelReady(channel, kTimeoutMs))
    throw std::runtime_error("Secure channel not ready.");

  return Aecs::NewStub(channel);
}

#define CHECK_STATUS(s) CheckStatusCode(s, __FUNCTION__)
TeeErrorCode ServiceAdminClient::CheckStatusCode(const Status& status,
                                                 const char* func) {
  if (!status.ok()) {
    TEE_LOG_ERROR("[%s] Status Code: %d", func, status.error_code());
    TEE_LOG_ERROR("Error Message: %s", status.error_message().c_str());
    return TEE_ERROR_UNEXPECTED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::GetServerPublicKey(
    const std::string& service_name) {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + std::chrono::milliseconds(kTimeoutMs));

  tee::AdminRemoteCallRequest request;
  tee::AdminRemoteCallResponse response;

  // If there is no AECS server public key, get it from server firstly
  DigitalEnvelopeEncrypted* req_enc = request.mutable_req_enc();
  TEE_CHECK_RETURN(AddAdminSignature(service_name, req_enc));
  request.set_function_name("GetIdentityPublicKey");
  Status status = stub_->ServiceAdminRemoteCall(&context, request, &response);
  TEE_CHECK_RETURN(CHECK_STATUS(status));
  TEE_CHECK_RETURN(CheckServerRaReport(response.auth_ra_report()));
  server_pubkey_ = response.auth_ra_report().public_key();

  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::RemoteCall(
    const std::string& service_name,
    const std::string& function_name,
    const google::protobuf::Message& req,
    google::protobuf::Message* res) {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + std::chrono::milliseconds(kTimeoutMs));

  tee::AdminRemoteCallRequest request;
  tee::AdminRemoteCallResponse response;

  if (server_pubkey_.empty()) {
    TEE_LOG_ERROR("Please get server public key firstly");
    return TEE_ERROR_UNEXPECTED;
  }

  // Serialize the original request, encrypt and sign it
  std::string req_str;
  PB_SERIALIZE(req, &req_str);
  request.set_function_name(function_name);
  TEE_CHECK_RETURN(EnvelopeEncryptAndSign(service_name,
                                          server_pubkey_,
                                          admin_prvkey_,
                                          req_str,
                                          request.mutable_req_enc()));

  // Call the remote trusted function
  Status status = stub_->ServiceAdminRemoteCall(&context, request, &response);
  TEE_CHECK_RETURN(CHECK_STATUS(status));

  // Verify the AECS server RA report
  TEE_CHECK_RETURN(CheckServerRaReport(response.auth_ra_report()));

  // Decrypt, verify signature and then return the function response
  if (!response.res_enc().aes_cipher().cipher().empty()) {
    std::string res_str;
    TEE_CHECK_RETURN(EnvelopeDecryptAndVerify(
        admin_prvkey_, server_pubkey_, response.res_enc(), &res_str));
    PB_PARSE(*res, res_str);
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

TeeErrorCode ServiceAdminClient::EnvelopeEncryptAndSign(
    const std::string& service_name,
    const std::string& encrypt_pubkey,
    const std::string& signing_prvkey,
    const std::string& plain,
    tee::DigitalEnvelopeEncrypted* env) {
  tee::common::DigitalEnvelope envelope(service_name);
  TEE_CHECK_RETURN(envelope.Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(envelope.Sign(signing_prvkey, plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::EnvelopeDecryptAndVerify(
    const std::string& decrypt_prvkey,
    const std::string& verify_pubkey,
    const tee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  tee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(decrypt_prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::CheckServerRaReport(
    const RaReportAuthentication& auth) {
  tee::common::RaChallenger verifier(auth.public_key(), server_info_);
  TEE_CHECK_RETURN(verifier.VerifyReport(auth.ias_report()));
  return TEE_SUCCESS;
}

TeeErrorCode ServiceAdminClient::AddAdminSignature(
    const std::string& service_name, DigitalEnvelopeEncrypted* env) {
  // Place the service name into aes_ciphre AAD field
  env->mutable_aes_cipher()->set_aad(service_name);

  // Calculate the service name hash and sign it
  tee::common::DataBytes service_name_hash(service_name);
  std::string* signature = env->mutable_plain_hash_sig();
  tee::common::RsaCrypto rsa;
  TEE_CHECK_RETURN(rsa.Sign(
      admin_prvkey_, service_name_hash.ToSHA256().GetStr(), signature));

  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
