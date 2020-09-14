#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

#include "untrusted/untrusted_aecs_client.h"

namespace aecs {
namespace untrusted {

AecsClient::AecsClient(const std::string& ep,
                       const std::string& ca,
                       const std::string& key,
                       const std::string& cert) {
  stub_ = PrepareSecureStub(ep, ca, key, cert);
}

bool AecsClient::WaitForChannelReady(std::shared_ptr<grpc::Channel> channel) {
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

std::unique_ptr<Aecs::Stub> AecsClient::PrepareSecureStub(
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

  if (!WaitForChannelReady(channel)) {
    throw std::runtime_error("Secure channel not ready.");
  }

  return Aecs::NewStub(channel);
}

TeeErrorCode AecsClient::CheckStatusCode(const Status& status) {
  if (!status.ok()) {
    TEE_LOG_ERROR("Status Code: %d", status.error_code());
    TEE_LOG_ERROR("Error Message: %s", status.error_message().c_str());
    return TEE_ERROR_UNEXPECTED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode AecsClient::GetRemoteSecret(const GetRemoteSecretRequest& request,
                                         GetRemoteSecretResponse* response) {
  Status status;
  ClientContext context;

  context.set_deadline(std::chrono::system_clock::now() +
                       std::chrono::milliseconds(kTimeoutMs));

  status = stub_->GetRemoteSecret(&context, request, response);
  return CheckStatusCode(status);
}

}  // namespace untrusted
}  // namespace aecs
