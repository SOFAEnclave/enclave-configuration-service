#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/untrusted_config.h"

#include "untrusted/untrusted_aecs_client.h"

#include "grpcpp/grpcpp.h"

namespace aecs {
namespace untrusted {

AecsClient::AecsClient() {
  // Load channel parameters based on configuration file
  std::string server = AECS_CONF_STR(kAecsConfRpcServer);
  std::string port = AECS_CONF_STR(kAecsConfRpcPort);
  std::string endpoint = server + ":" + port;

  std::string ssl_secure = AECS_CONF_STR(kAecsConfRpcSslSecure);
  if (IsSecureChannel(ssl_secure)) {
    std::string ssl_ca = AECS_CONF_FILE_STR(kAecsConfRpcSslCa);
    std::string ssl_key = AECS_CONF_FILE_STR(kAecsConfRpcSslKey);
    std::string ssl_cert = AECS_CONF_FILE_STR(kAecsConfRpcSslCert);
    stub_ =
        Aecs::NewStub(CreateSecureChannel(endpoint, ssl_ca, ssl_key, ssl_cert));
  } else {
    stub_ = Aecs::NewStub(CreateInsecureChannel(endpoint));
  }
}

AecsClient::AecsClient(const std::string& endpoint) {
  stub_ = Aecs::NewStub(CreateInsecureChannel(endpoint));
}

TeeErrorCode AecsClient::GetEnclaveSecret(
    const GetEnclaveSecretRequest& request,
    GetEnclaveSecretResponse* response) {
  Status status;
  ClientContext context;

  context.set_deadline(std::chrono::system_clock::now() +
                       std::chrono::milliseconds(kTimeoutMs));

  status = stub_->GetEnclaveSecret(&context, request, response);
  return CheckStatusCode(status);
}

TeeErrorCode AecsClient::GetEnclaveSecretPublic(
    const kubetee::GetEnclaveSecretPublicRequest& request,
    kubetee::GetEnclaveSecretPublicResponse* response) {
  Status status;
  ClientContext context;

  context.set_deadline(std::chrono::system_clock::now() +
                       std::chrono::milliseconds(kTimeoutMs));

  status = stub_->GetEnclaveSecretPublic(&context, request, response);
  return CheckStatusCode(status);
}

}  // namespace untrusted
}  // namespace aecs
