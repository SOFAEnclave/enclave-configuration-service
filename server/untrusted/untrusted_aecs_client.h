#ifndef SERVER_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_
#define SERVER_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "./aecs_service.grpc.pb.h"
#include "./aecs_service.pb.h"

using grpc::ClientContext;
using grpc::Status;

using kubetee::Aecs;
using kubetee::AecsAdminInitializeRequest;
using kubetee::AecsAdminInitializeResponse;
using kubetee::GetRemoteSecretRequest;
using kubetee::GetRemoteSecretResponse;
using kubetee::IasReport;
using kubetee::UnifiedAttestationAuthReport;

namespace aecs {
namespace untrusted {

constexpr int kAecsClientTimeoutMs = 10000;

class AecsClient : public kubetee::untrusted::TeeGrpcClient {
 public:
  AecsClient(const std::string& endpoint,
             const std::string& ssl_secure,
             const std::string& ssl_ca,
             const std::string& ssl_key,
             const std::string& ssl_cert);
  ~AecsClient() {}

  TeeErrorCode GetRemoteSecret(const GetRemoteSecretRequest& request,
                               GetRemoteSecretResponse* response);

 private:
  std::unique_ptr<Aecs::Stub> stub_;
};

}  // namespace untrusted
}  // namespace aecs

#endif  // SERVER_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_
