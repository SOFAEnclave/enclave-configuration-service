#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "untrusted/untrusted_aecs_client.h"

namespace aecs {
namespace untrusted {

AecsClient::AecsClient(const std::string& endpoint,
                       const std::string& ssl_secure,
                       const std::string& ssl_ca,
                       const std::string& ssl_key,
                       const std::string& ssl_cert) {
  stub_ = Aecs::NewStub(
      CreateChannel(endpoint, ssl_secure, ssl_ca, ssl_key, ssl_cert));
}

TeeErrorCode AecsClient::GetRemoteSecret(const GetRemoteSecretRequest& request,
                                         GetRemoteSecretResponse* response) {
  Status status;
  ClientContext context;

  context.set_deadline(std::chrono::system_clock::now() +
                       std::chrono::milliseconds(kAecsClientTimeoutMs));

  status = stub_->GetRemoteSecret(&context, request, response);
  return CheckStatusCode(status);
}

}  // namespace untrusted
}  // namespace aecs
