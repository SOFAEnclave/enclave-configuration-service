#ifndef CLIENT_CPP_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_
#define CLIENT_CPP_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_

#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "unified_attestation/ua_untrusted.h"
#include "grpc/untrusted_grpc_client.h"

#include "aecs/untrusted_enclave.h"

#include "./aecs_service.grpc.pb.h"
#include "./aecs_service.pb.h"

using grpc::ClientContext;
using grpc::Status;

using kubetee::Aecs;
using kubetee::GetEnclaveSecretRequest;
using kubetee::GetEnclaveSecretResponse;
using kubetee::IasReport;
using kubetee::UnifiedAttestationAuthReport;

namespace aecs {
namespace untrusted {

constexpr int kTimeoutMs = 4000;
constexpr char kSelfSignedCN[] = "enclave-service";

class AecsClient : public kubetee::untrusted::TeeGrpcClient {
 public:
  AecsClient();
  explicit AecsClient(const std::string& endpoint);
  ~AecsClient() {}

  TeeErrorCode GetEnclaveSecret(const GetEnclaveSecretRequest& request,
                                GetEnclaveSecretResponse* response);

  TeeErrorCode GetEnclaveSecretPublic(
      const kubetee::GetEnclaveSecretPublicRequest& request,
      kubetee::GetEnclaveSecretPublicResponse* response);

 private:
  std::unique_ptr<Aecs::Stub> stub_;
};

}  // namespace untrusted
}  // namespace aecs

#endif  // CLIENT_CPP_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_
