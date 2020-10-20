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
#include "tee/untrusted/utils/untrusted_fs.h"

#include "aecsadmin/aecsadmin_grpc_client.h"

namespace aecs {
namespace client {

AecsAdminClient::AecsAdminClient(const std::string& ep,
                                 const std::string& ca,
                                 const std::string& key,
                                 const std::string& cert,
                                 const std::string& admin_prvkey,
                                 const std::string& admin_passwd,
                                 const tee::EnclaveMatchRules& enclave_info)
    : admin_prvkey_(admin_prvkey),
      admin_passwd_(admin_passwd),
      server_info_(enclave_info) {
  stub_ = PrepareSecureStub(ep, ca, key, cert);
}

bool AecsAdminClient::WaitForChannelReady(
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

std::unique_ptr<Aecs::Stub> AecsAdminClient::PrepareSecureStub(
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

  // For our generated certificates CN.
  channel_args.SetSslTargetNameOverride(kSelfSignedCN);

  // Return a channel using the credentials created in the previous step.
  auto channel = grpc::CreateCustomChannel(ep, ssl_creds, channel_args);

  if (!WaitForChannelReady(channel, kTimeoutMs))
    throw std::runtime_error("Secure channel not ready.");

  return Aecs::NewStub(channel);
}

#define CHECK_STATUS(s) CheckStatusCode(s, __FUNCTION__)
TeeErrorCode AecsAdminClient::CheckStatusCode(const Status& status,
                                              const char* func) {
  if (!status.ok()) {
    TEE_LOG_ERROR("[%s] Status Code: %d", func, status.error_code());
    TEE_LOG_ERROR("Error Message: %s", status.error_message().c_str());
    return TEE_ERROR_UNEXPECTED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::GetServerPublicKey() {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + std::chrono::milliseconds(kTimeoutMs));

  tee::AdminRemoteCallRequest request;
  tee::AdminRemoteCallResponse response;

  // If there is no server public key, get it from server firstly
  TEE_CHECK_RETURN(AddAdminSignature(request.mutable_req_enc()));
  request.set_function_name("GetIdentityPublicKey");
  Status status = stub_->AecsAdminRemoteCall(&context, request, &response);
  TEE_CHECK_RETURN(CHECK_STATUS(status));
  TEE_CHECK_RETURN(CheckServerRaReport(response.auth_ra_report()));
  server_pubkey_ = response.auth_ra_report().public_key();

  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::RemoteCall(const std::string& function_name,
                                         const google::protobuf::Message& req,
                                         google::protobuf::Message* res) {
  ClientContext context;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  context.set_deadline(now + std::chrono::milliseconds(kTimeoutMs));

  tee::AdminRemoteCallRequest request;
  tee::AdminRemoteCallResponse response;

  if (server_pubkey_.empty()) {
    TEE_LOG_ERROR("Invalid AECS server public key");
    return TEE_ERROR_UNEXPECTED;
  }

  // Serialize the original request, encrypt and sign it
  // Append sequence number to avoid replay attack
  std::string req_str;
  PB_SERIALIZE(req, &req_str);
  tee::AdminRemoteCallReqWithAuth remote_req;
  remote_req.set_req(req_str);
  remote_req.set_password_hash(admin_passwd_);
  // Read/Update the sequence number from/to file
  using tee::untrusted::FsReadString;
  using tee::untrusted::FsWriteString;
  std::string sequence_str;
  // The sequence file may doesn't exist when first time
  tee::untrusted::FsReadString(kSequenceFile, &sequence_str);
  int64_t sequence = sequence_str.empty() ? 1 : std::stoi(sequence_str) + 1;
  remote_req.set_sequence(sequence);
  TEE_CHECK_RETURN(FsWriteString(kSequenceFile, std::to_string(sequence)));
  // Get the final remote call request string
  std::string remote_req_str;
  PB_SERIALIZE(remote_req, &remote_req_str);

  request.set_function_name(function_name);
  TEE_CHECK_RETURN(EnvelopeEncryptAndSign(server_pubkey_,
                                          admin_prvkey_,
                                          remote_req_str,
                                          request.mutable_req_enc()));

  // Call the remote trusted function
  Status status = stub_->AecsAdminRemoteCall(&context, request, &response);
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

TeeErrorCode AecsAdminClient::AecsProvision(const AecsProvisionRequest& req,
                                            AecsProvisionResponse* res) {
  TEE_CHECK_RETURN(RemoteCall("AecsProvision", req, res));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::EnvelopeEncryptAndSign(
    const std::string& encrypt_pubkey,
    const std::string& signing_prvkey,
    const std::string& plain,
    tee::DigitalEnvelopeEncrypted* env) {
  tee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Encrypt(encrypt_pubkey, plain, env));
  TEE_CHECK_RETURN(envelope.Sign(signing_prvkey, plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::EnvelopeDecryptAndVerify(
    const std::string& decrypt_prvkey,
    const std::string& verify_pubkey,
    const tee::DigitalEnvelopeEncrypted& env,
    std::string* plain) {
  tee::common::DigitalEnvelope envelope;
  TEE_CHECK_RETURN(envelope.Decrypt(decrypt_prvkey, env, plain));
  TEE_CHECK_RETURN(envelope.Verify(verify_pubkey, *plain, env));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::CheckServerRaReport(
    const RaReportAuthentication& auth) {
  tee::common::RaChallenger verifier(auth.public_key(), server_info_);
  TEE_CHECK_RETURN(verifier.VerifyReport(auth.ias_report()));
  return TEE_SUCCESS;
}

TeeErrorCode AecsAdminClient::AddAdminSignature(DigitalEnvelopeEncrypted* env) {
  tee::common::DataBytes random_hash;
  random_hash.Randomize(32).ToSHA256().Void();

  // For AECS administrator authentication
  // Only set the hash and signature field in DigitalEnvelopeEncrypted
  env->set_plain_hash(random_hash.GetStr());
  std::string* signature = env->mutable_plain_hash_sig();

  tee::common::RsaCrypto rsa;
  TEE_CHECK_RETURN(rsa.Sign(admin_prvkey_, random_hash.GetStr(), signature));

  return TEE_SUCCESS;
}

}  // namespace client
}  // namespace aecs
