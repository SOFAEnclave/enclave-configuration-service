#ifndef SERVER_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_
#define SERVER_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

#include "./aecs_service.grpc.pb.h"
#include "./aecs_service.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using tee::Aecs;
using tee::AecsAdminInitializeRequest;
using tee::AecsAdminInitializeResponse;
using tee::GetRemoteSecretRequest;
using tee::GetRemoteSecretResponse;
using tee::IasReport;
using tee::RaReportAuthentication;

namespace aecs {
namespace untrusted {

constexpr int kTimeoutMs = 4000;
constexpr char kSelfSignedCN[] = "enclave-service";

class AecsClient {
 public:
  AecsClient(const std::string& ep,
             const std::string& ca,
             const std::string& key,
             const std::string& cert);
  ~AecsClient() {}

  std::unique_ptr<Aecs::Stub> PrepareSecureStub(const std::string& ep,
                                                const std::string& ca,
                                                const std::string& key,
                                                const std::string& cert);

  TeeErrorCode GetRemoteSecret(const GetRemoteSecretRequest& request,
                               GetRemoteSecretResponse* response);

 private:
  bool WaitForChannelReady(std::shared_ptr<Channel> channel);
  TeeErrorCode CheckStatusCode(const Status& status);

  std::unique_ptr<Aecs::Stub> stub_;
};

}  // namespace untrusted
}  // namespace aecs

#endif  // SERVER_UNTRUSTED_UNTRUSTED_AECS_CLIENT_H_
