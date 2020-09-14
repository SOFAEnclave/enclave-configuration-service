#include <memory>
#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"

#include "tee/common/aes.h"
#include "tee/common/challenger.h"
#include "tee/common/rsa.h"

#include "tee/untrusted/enclave/untrusted_enclave.h"
#include "tee/untrusted/ra/untrusted_challenger.h"
#include "tee/untrusted/ra/untrusted_ias.h"
#include "tee/untrusted/untrusted_config.h"
#include "tee/untrusted/untrusted_pbcall.h"
#include "tee/untrusted/utils/untrusted_json.h"

#include "untrusted/untrusted_aecs_client.h"
#include "untrusted/untrusted_aecs_server.h"

#include "./enclave_u.h"

static const char kEnclaveSecretNameAll[] = "All";

namespace aecs {
namespace untrusted {

TeeErrorCode AecsServiceImpl::GetServerRaAuthentication(
    RaReportAuthentication* auth) {
  auth->mutable_ias_report()->CopyFrom(enclave_->GetLocalIasReport());
  auth->set_public_key(enclave_->GetPublicKey());
  return TEE_SUCCESS;
}

Status AecsServiceImpl::GetRemoteSecret(ServerContext* context,
                                        const GetRemoteSecretRequest* req,
                                        GetRemoteSecretResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Populate the response with server's envelope encrypted identity keys
  // For Identity, we will verify the remote enclave RA report in trusted
  // Now the mrsigner and prodid need to be the same with current enclave
  TeeErrorCode ret = enclave_->TeeRun(
      "TeeGetRemoteSecret", *req, res->mutable_secret_keys_enc());
  if (ret != TEE_SUCCESS) {
    RETURN_ERROR("Fail to get encrypted identity keys");
  }

  // Populate the response with server's RA report and public key
  RaReportAuthentication* server_ra_auth = res->mutable_auth_ra_report();
  if (GetServerRaAuthentication(server_ra_auth) != TEE_SUCCESS) {
    RETURN_ERROR("Fail to load server RA report");
  }

  return Status::OK;
}

Status AecsServiceImpl::AecsAdminRemoteCall(ServerContext* context,
                                            const AdminRemoteCallRequest* req,
                                            AdminRemoteCallResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Call the trusted function
  std::string name = req->function_name();
  TEE_LOG_DEBUG("AECS admin remote call: %s", name.c_str());
  TeeErrorCode ret = enclave_->TeeRun("TeeAecsAdminRemoteCall", *req, res);
  if (ret != TEE_SUCCESS) {
    RETURN_ERROR("Fail to call AECS admin remote function");
  }

  // Return server's RA report and identity public key
  RaReportAuthentication* server_auth = res->mutable_auth_ra_report();
  if (GetServerRaAuthentication(server_auth) != TEE_SUCCESS) {
    RETURN_ERROR("Fail to load server RA report");
  }

  // Special case to deal with the sealed identity key backup from storage
  // It's a little ugly here, but all the response in function
  // response are end-to-end encrypted to administrator client.
  if (req->function_name() == "AecsProvision" &&
      !res->sealed_secret().empty()) {
    TEE_LOG_INFO("Initialize enclave again with storage identity key backup");
    // Generate new quote and report after the new key pair's been replaced
    // Initialize service implement again to update cached report and public key
    if (enclave_->Initialize(res->sealed_secret()) != TEE_SUCCESS) {
      RETURN_ERROR("Fail to initialize the enclave with sealed identity keys");
    }
    if ((enclave_->FetchIasReport(false))) {
      RETURN_ERROR("Fail to fetch the IAS report based on new identity keys");
    }
    if (InitializeServerImpl(enclave_) != TEE_SUCCESS) {
      RETURN_ERROR("Fail toe initialize the rpc server again");
    }
  }

  return Status::OK;
}

Status AecsServiceImpl::ServiceAdminRemoteCall(
    ServerContext* context,
    const AdminRemoteCallRequest* req,
    AdminRemoteCallResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Call the trusted function
  std::string name = req->function_name();
  TEE_LOG_DEBUG("Service admin remote call: %s", name.c_str());
  TeeErrorCode ret = enclave_->TeeRun("TeeServiceAdminRemoteCall", *req, res);
  if (ret != TEE_SUCCESS) {
    RETURN_ERROR("Fail to call service admin remote function");
  }

  // Return server's RA report and identity public key
  RaReportAuthentication* server_auth = res->mutable_auth_ra_report();
  if (GetServerRaAuthentication(server_auth) != TEE_SUCCESS) {
    RETURN_ERROR("Fail to load server RA report");
  }

  return Status::OK;
}

Status AecsServiceImpl::GetEnclaveSecret(ServerContext* context,
                                         const GetEnclaveSecretRequest* req,
                                         GetEnclaveSecretResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Check the service and secret name
  if (req->service_name().empty()) {
    RETURN_ERROR("Service name should not be empty");
  }
  if (req->secret_name().empty()) {
    RETURN_ERROR("Secret name should not be empty");
  }

  GetEnclaveSecretRequest request = *req;
  tee::RaReportAuthentication* auth = request.mutable_auth_ra_report();
  // For normal case, the request will include the IAS report
  // If the signature is empty, it means there is only quote,
  // And AECS will work as service provider to conect to IAS.
  if (auth->ias_report().b64_signature().empty()) {
    // For the IAS connection proxy case, only quote is sent.
    if (auth->ias_report().b64_quote_body().empty()) {
      RETURN_ERROR("At least quote body should be provided");
    }
    tee::untrusted::RaIasClient ias_client;
    if (ias_client.FetchReport(auth->ias_report().b64_quote_body(),
                               auth->mutable_ias_report()) != TEE_SUCCESS) {
      RETURN_ERROR("Fail to get IAS report based on the quote");
    }
  }

  // Get the encrypted enclave secret
  if (enclave_->TeeRun("TeeGetEnclaveSecret", request, res) != TEE_SUCCESS) {
    RETURN_ERROR("Fail to get enclave secret keys");
  }

  // Prepare response with server's RA report and public key
  RaReportAuthentication* server_ra_auth = res->mutable_auth_ra_report();
  if (GetServerRaAuthentication(server_ra_auth) != TEE_SUCCESS) {
    RETURN_ERROR("Fail to load server RA report");
  }

  return Status::OK;
}

TeeErrorCode AecsServiceImpl::InitializeServerImpl(EnclaveInstance* enclave) {
  enclave_ = enclave;

  // Check the server IAS report
  if (enclave_->GetLocalIasReport().b64_signature().empty()) {
    TEE_LOG_ERROR("Invalid server enclave identity public key");
    return TEE_ERROR_ENCLAVE_NOTINITIALIZED;
  }

  // Get the server identity publick key
  if (enclave_->GetPublicKey().empty()) {
    TEE_LOG_ERROR("Invalid server enclave identity public key");
    return TEE_ERROR_ENCLAVE_NOTINITIALIZED;
  }
  return TEE_SUCCESS;
}

// Nothing to do, all things done in InitServer()
AecsServer::AecsServer() : enclave_(nullptr) {}

TeeErrorCode AecsServer::InitServer(EnclaveInstance* enclave) {
  // Set and check the enclave instance
  enclave_ = enclave;
  if (enclave_ == 0) {
    TEE_LOG_ERROR("Invalid enclave ID on which to run RPC server");
    return TEE_ERROR_PARAMETERS;
  }

  // Load configurations
  std::string cert = GET_CONF_STR(tee::untrusted::kConfRpcCertPath);
  std::string key = GET_CONF_STR(tee::untrusted::kConfRpcKeyPath);
  std::string ca = GET_CONF_STR(tee::untrusted::kConfRpcCaPath);

  TeeErrorCode ret = tee::untrusted::FsReadString(cert, &ssl_cert_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to load ssl cert file: %s", cert.c_str());
    return ret;
  }
  ret = tee::untrusted::FsReadString(key, &ssl_key_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to load ssl key file: %s", key.c_str());
    return ret;
  }
  ret = tee::untrusted::FsReadString(ca, &ssl_ca_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to load ssl ca file: %s", ca.c_str());
    return ret;
  }

  root_server_ = GET_CONF_STR(tee::untrusted::kConfRpcRemoteServer);
  if (root_server_.empty()) {
    const char* proot = getenv("AECS_ROOT_SERVER");
    if (proot) {
      root_server_.assign(proot);
    }
  }
  root_port_ = GET_CONF_STR(tee::untrusted::kConfRpcRemotePort);
  if (root_port_.empty()) {
    const char* pport = getenv("AECS_ROOT_PORT");
    if (pport) {
      root_port_.assign(pport);
    }
  }
  rpc_port_ = GET_CONF_STR(tee::untrusted::kConfRpcPort);

  // Always generate new IAS report when start the service
  ret = enclave_->FetchIasReport(false);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to initialize the aecs local RA report: 0x%x", ret);
    return ret;
  }

  // Try to initialize the rpc server implement instance.
  // Must before sync identity because we will use the server ias_report
  // which is initialized in this process.
  ret = service_impl_.InitializeServerImpl(enclave_);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to initialize the RPC server implement instance");
    return ret;
  }

  // To check whether need to sync identity key from remote server
  TEE_CHECK_RETURN(SyncIdentityKeysFromRemote());

  return TEE_SUCCESS;
}

TeeErrorCode AecsServer::RunServer() {
  // Listen on the given address with authentication mechanism.
  SslServerCredentialsOptions::PemKeyCertPair keycert{ssl_key_, ssl_cert_};
  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = ssl_ca_;
  ssl_opts.pem_key_cert_pairs.push_back(keycert);
  ssl_opts.client_certificate_request =
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;

  ServerBuilder builder;
  std::string server_addr = "0.0.0.0:" + rpc_port_;
  builder.AddListeningPort(server_addr, grpc::SslServerCredentials(ssl_opts));
  // Register "AecsServiceImpl" as the instance through which we'll
  // communicate with clients. In this case it corresponds to an
  // *synchronous* service.
  builder.RegisterService(&service_impl_);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  TEE_LOG_INFO("Server listening on %s", server_addr.c_str());

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

TeeErrorCode AecsServer::SyncIdentityKeysFromRemote() {
  // If the remote root server has been specified for this AECS,
  // Sync the identity key pair from the remote root service firstly.
  // Otherwise, do nothing and return success.
  if (root_server_.empty()) {
    return TEE_SUCCESS;
  }

  std::string root_aecs_endpoint = root_server_ + ":" + root_port_;
  TEE_LOG_INFO("Sync identity from remote: %s", root_aecs_endpoint.c_str());

  // Get the remote identity
  GetRemoteSecretRequest req;
  GetRemoteSecretResponse res;
  AecsClient secure_client(root_aecs_endpoint, ssl_ca_, ssl_key_, ssl_cert_);
  RaReportAuthentication* auth_ra_report = req.mutable_auth_ra_report();
  service_impl_.GetServerRaAuthentication(auth_ra_report);
  TEE_CHECK_RETURN(secure_client.GetRemoteSecret(req, &res));

  // Now get remote identity sealed by current enclave
  // The result is the same as we load the identity keys from cached file
  TEE_LOG_INFO("Replace local identity with what from remote root aecs");
  PbGenericResponse sealed_res;
  TEE_CHECK_RETURN(enclave_->TeeRun("TeeUnpackRemoteSecret", res, &sealed_res));
  if ((sealed_res.result_size() == 0) || sealed_res.result()[0].empty()) {
    TEE_LOG_ERROR("Fail to seal encrypted remote identity keys");
    return TEE_ERROR_UNEXPECTED;
  }

  // Generate new quote and report after the new key pair's been replaced
  // Initialize service implement again to update cached report and public key
  TEE_CHECK_RETURN(enclave_->Initialize(sealed_res.result()[0]));
  TEE_CHECK_RETURN(enclave_->FetchIasReport(false));
  TEE_CHECK_RETURN(service_impl_.InitializeServerImpl(enclave_));

  TEE_LOG_INFO("Sync identity Successfully!");
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace aecs
