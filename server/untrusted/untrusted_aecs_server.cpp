#include <memory>
#include <string>
#include <vector>

#include "aecs/error.h"
#include "aecs/untrusted_enclave.h"

#include "untrusted/untrusted_aecs_client.h"
#include "untrusted/untrusted_aecs_config.h"
#include "untrusted/untrusted_aecs_server.h"

#include "./enclave_u.h"

namespace aecs {
namespace untrusted {

TeeErrorCode AecsServiceImpl::GetServerRaAuthentication(
    UnifiedAttestationAuthReport* auth) {
  auth->CopyFrom(enclave_->GetLocalAuthReport());
  return TEE_SUCCESS;
}

TeeErrorCode AecsServiceImpl::AecsSyncFromRemote(const std::string& endpoint) {
  // Check the remote endpoint
  TEE_LOG_INFO("Sync identity from remote: %s", endpoint.c_str());
  if (endpoint.empty()) {
    return AECS_ERROR_SERVER_REMOTE_ENDPOINT;
  }

  // Get the untrusted enclave instance
  EnclavesManager& enclaves_mgr = EnclavesManager::GetInstance();
  EnclaveInstance* enclave = enclaves_mgr.GetEnclaveByName(kAecsServerName);

  // Get the remote identity
  kubetee::GetRemoteSecretRequest req;
  kubetee::GetRemoteSecretResponse res;
  req.mutable_auth_ra_report()->CopyFrom(enclave->GetLocalAuthReport());

  std::string ssl_secure, ssl_ca, ssl_key, ssl_cert;
  TEE_CHECK_RETURN(AecsGetRpcConfig(&ssl_secure, &ssl_ca, &ssl_key, &ssl_cert));
  AecsClient aecs_client(endpoint, ssl_secure, ssl_ca, ssl_key, ssl_cert);
  TEE_CHECK_RETURN(aecs_client.GetRemoteSecret(req, &res));

  // Now get remote identity sealed by current enclave
  // The result is the same as we load the identity keys from cached file
  TEE_LOG_INFO("Replace local identity by what from remote root aecs");
  kubetee::UnifiedFunctionGenericResponse sealed_res;
  TEE_CHECK_RETURN(enclave->TeeRun("TeeUnpackRemoteSecret", res, &sealed_res));
  if ((sealed_res.result_size() == 0) || sealed_res.result()[0].empty()) {
    TEE_LOG_ERROR("Fail to seal encrypted remote identity keys");
    return AECS_ERROR_ENCLAVE_SEALED_REMOTE_IDENTITY;
  }

  // Generate new quote and report after the new key pair's been replaced
  TEE_CHECK_RETURN(enclave->Initialize(sealed_res.result()[0]));
  TEE_CHECK_RETURN(enclave->CreateRaReport(false));

  // Check the new attestation report and public key
  if (enclave->GetLocalAuthReport().report().json_report().empty()) {
    TEE_LOG_ERROR("Invalid server enclave attestation report");
    return AECS_ERROR_ENCLAVE_NO_RA_REPORT;
  }
  if (enclave->GetPublicKey().empty()) {
    TEE_LOG_ERROR("Invalid server enclave identity public key");
    return AECS_ERROR_ENCLAVE_NO_PUBLIC_KEY;
  }

  TEE_LOG_INFO("Sync identity Successfully!");
  return TEE_SUCCESS;
}

Status AecsServiceImpl::GetAecsStatus(ServerContext* context,
                                      const GetAecsStatusRequest* req,
                                      GetAecsStatusResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  TeeErrorCode ret = enclave_->TeeRun("TeeGetEnclaveStatus", *req, res);
  RETURN_ERROR(ret, "Fail to get enclave status");

  // Populate the response with server's RA report and public key
  UnifiedAttestationAuthReport* server_ra_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_ra_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::SyncWithRemoteAecs(ServerContext* context,
                                           const SyncWithRemoteAecsRequest* req,
                                           SyncWithRemoteAecsResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Trigger the AECS sync in untrsuted side directly
  TeeErrorCode ret = AecsSyncFromRemote(req->remote_endpoint());
  RETURN_ERROR(ret, "Fail to sync to remote aecs server");

  // Populate the response with server's RA report and public key
  UnifiedAttestationAuthReport* server_ra_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_ra_auth);

  // Anyway, will return the newest status
  GetAecsStatusRequest status_req;
  GetAecsStatusResponse status_res;
  TeeErrorCode rc = TEE_SUCCESS;
  rc = enclave_->TeeRun("TeeGetEnclaveStatus", status_req, &status_res);
  res->set_status_str(status_res.status_str());
  res->mutable_status_sig()->CopyFrom(status_res.status_sig());

  if (ret != TEE_SUCCESS) {
    RETURN_ERROR(ret, "Fail to load server RA report");
  } else if (rc != TEE_SUCCESS) {
    RETURN_ERROR(rc, "Fail to get enclave status");
  }

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::GetRemoteSecret(ServerContext* context,
                                        const GetRemoteSecretRequest* req,
                                        GetRemoteSecretResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Populate the response with server's envelope encrypted identity keys
  // For Identity, we will verify the remote enclave RA report in trusted
  // Now the mrsigner and prodid need to be the same with current enclave
  TEE_LOG_INFO("Aecs Enclave remote call: GetRemoteSecret");
  TeeErrorCode ret = enclave_->TeeRun("TeeGetRemoteSecret", *req,
                                      res->mutable_secret_keys_enc());
  RETURN_ERROR(ret, "Fail to get encrypted identity keys");

  // Populate the response with server's RA report and public key
  UnifiedAttestationAuthReport* server_ra_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_ra_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::AecsAdminRemoteCall(ServerContext* context,
                                            const AdminRemoteCallRequest* req,
                                            AdminRemoteCallResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Call the trusted function
  std::string name = req->function_name();
  TEE_LOG_INFO("AECS admin remote call: %s", name.c_str());
  TeeErrorCode ret = enclave_->TeeRun("TeeAecsAdminRemoteCall", *req, res);
  RETURN_ERROR(ret, "Fail to call AECS admin remote function");

  // Return server's RA report and identity public key
  UnifiedAttestationAuthReport* server_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  // Special case to deal with the sealed identity key backup from storage
  // It's a little ugly here, but all the response in function response are
  // end-to-end encrypted to administrator client.
  if (req->function_name() == "AecsProvision" && !res->res_plain().empty()) {
    TEE_LOG_INFO("Initialize enclave again with storage identity key backup");
    // Generate new quote and report after the new key pair's been replaced
    // Initialize service implement again to update cached report and public key
    ret = enclave_->Initialize(res->res_plain());
    RETURN_ERROR(ret, "Fail to initialize the enclave with sealed identity");

    ret = enclave_->CreateRaReport(false);
    RETURN_ERROR(ret, "Fail to fetch the IAS report with new identity keys");

    ret = InitializeServerImpl(enclave_);
    RETURN_ERROR(ret, "Fail toe initialize the rpc server again");
  }

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::ServiceAdminRemoteCall(
    ServerContext* context,
    const AdminRemoteCallRequest* req,
    AdminRemoteCallResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Call the trusted function
  std::string name = req->function_name();
  TEE_LOG_INFO("Service admin remote call: %s", name.c_str());
  TeeErrorCode ret = enclave_->TeeRun("TeeServiceAdminRemoteCall", *req, res);
  RETURN_ERROR(ret, "Fail to call service admin remote function");

  // Return server's RA report and identity public key
  UnifiedAttestationAuthReport* server_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::GetEnclaveSecret(ServerContext* context,
                                         const GetEnclaveSecretRequest* req,
                                         GetEnclaveSecretResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Check the service and secret name
  if (req->service_name().empty()) {
    RETURN_ERROR(AECS_ERROR_SECRET_GET_EMPTY_SERVICE_NAME,
                 "Service name should not be empty");
  }
  if (req->secret_name().empty()) {
    RETURN_ERROR(AECS_ERROR_SECRET_GET_EMPTY_SECRET_NAME,
                 "Secret name should not be empty");
  }

  // Get the encrypted enclave secret
  TeeErrorCode ret = enclave_->TeeRun("TeeGetEnclaveSecret", *req, res);
  RETURN_ERROR(ret, "Fail to get enclave secret keys");

  // Prepare response with server's RA report and public key
  UnifiedAttestationAuthReport* server_ra_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_ra_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::GetEnclaveSecretPublic(
    ServerContext* context,
    const GetEnclaveSecretPublicRequest* req,
    GetEnclaveSecretPublicResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Check the service and secret name
  if (req->service_name().empty()) {
    RETURN_ERROR(AECS_ERROR_SECRET_GETPUB_EMPTY_SERVICE_NAME,
                 "Service name should not be empty");
  }
  if (req->secret_name().empty()) {
    RETURN_ERROR(AECS_ERROR_SECRET_GETPUB_EMPTY_SECRET_NAME,
                 "Secret name should not be empty");
  }

  // Get the enclave secret public key and signature
  TeeErrorCode ret = enclave_->TeeRun("TeeGetEnclaveSecretPublic", *req, res);
  RETURN_ERROR(ret, "Fail to get enclave secret public key");

  // Prepare response with server's RA report and public key
  UnifiedAttestationAuthReport* server_ra_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_ra_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::CreateTaSecret(ServerContext* context,
                                       const CreateTaSecretRequest* req,
                                       CreateTaSecretResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Check the secret name
  if (req->secret().spec().secret_name().empty()) {
    RETURN_ERROR(AECS_ERROR_SECRET_GETPUB_EMPTY_SECRET_NAME,
                 "Secret name should not be empty");
  }

  // Create the enclave secret
  TeeErrorCode ret = enclave_->TeeRun("TeeCreateTaSecret", *req, res);
  RETURN_ERROR(ret, "Fail to create trusted application bound secret");

  // Prepare response with server's RA report and public key
  UnifiedAttestationAuthReport* server_ra_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_ra_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

Status AecsServiceImpl::DestroyTaSecret(ServerContext* context,
                                        const DestroyTaSecretRequest* req,
                                        DestroyTaSecretResponse* res) {
  GRPC_INTERFACE_ENTER_DEBUG();

  // Check the secret name
  if (req->secret_name().empty()) {
    RETURN_ERROR(AECS_ERROR_SECRET_GETPUB_EMPTY_SECRET_NAME,
                 "Secret name should not be empty");
  }

  // Create the enclave secret
  TeeErrorCode ret = enclave_->TeeRun("TeeDestroyTaSecret", *req, res);
  RETURN_ERROR(ret, "Fail to delete trusted application bound secret");

  // Prepare response with server's RA report and public key
  UnifiedAttestationAuthReport* server_ra_auth = res->mutable_auth_ra_report();
  ret = GetServerRaAuthentication(server_ra_auth);
  RETURN_ERROR(ret, "Fail to load server RA report");

  GRPC_INTERFACE_EXIT_DEBUG();
  return Status::OK;
}

TeeErrorCode AecsServiceImpl::InitializeServerImpl(EnclaveInstance* enclave) {
  enclave_ = enclave;

  // Check the server attestation report
  if (enclave_->GetLocalAuthReport().report().json_report().empty()) {
    TEE_LOG_ERROR("Invalid server enclave attestation report");
    return AECS_ERROR_ENCLAVE_NO_RA_REPORT;
  }

  // Get the server identity public key
  if (enclave_->GetPublicKey().empty()) {
    TEE_LOG_ERROR("Invalid server enclave identity public key");
    return AECS_ERROR_ENCLAVE_NO_PUBLIC_KEY;
  }

  return TEE_SUCCESS;
}

TeeErrorCode AecsServer::InitServer(EnclaveInstance* enclave) {
  // Set and check the enclave instance
  enclave_ = enclave;
  if ((!enclave_) || enclave_->GetEnclaveID().empty()) {
    TEE_LOG_ERROR("Emptt tee identity on which to run RPC server");
    return AECS_ERROR_ENCLAVE_INVALID_ID;
  }

  // Load configurations
  TEE_CHECK_RETURN(
      AecsGetRpcConfig(&ssl_secure_, &ssl_ca_, &ssl_key_, &ssl_cert_));

  // Use the environment variable to replace the value in config file
  TEE_CHECK_RETURN(AecsGetEnvConfig(&root_server_, &root_port_, &rpc_port_));

  // Always create new attestation report when start the service
  TEE_CHECK_RETURN(enclave_->CreateRaReport(false));

  // Try to initialize the rpc server implement instance.
  // Must before sync identity because we will use the server ias_report
  // which is initialized in this process.
  TEE_CHECK_RETURN(service_impl_.InitializeServerImpl(enclave_));

  // To check whether need to sync identity key from remote server
  TEE_CHECK_RETURN(SyncIdentityKeysFromRemote());

  return TEE_SUCCESS;
}

TeeErrorCode AecsServer::RunServer() {
  std::string server_addr = "0.0.0.0:" + rpc_port_;
  std::shared_ptr<grpc::ServerBuilder> builder =
      CreateBuilder(server_addr, ssl_secure_, ssl_ca_, ssl_key_, ssl_cert_);

  // Register "AecsServiceImpl" as the instance through which we'll
  // communicate with clients. In this case it corresponds to an
  // *synchronous* service.
  builder->RegisterService(&service_impl_);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder->BuildAndStart());
  TEE_LOG_INFO("Server listening on %s", server_addr.c_str());

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
  return TEE_SUCCESS;
}

TeeErrorCode AecsServer::SyncIdentityKeysFromRemote() {
  // If the remote root server has been specified for this AECS,
  // Sync the identity key pair from the remote root service firstly.
  // Otherwise, do nothing and return success.
  if (!root_server_.empty()) {
    std::string endpoint = root_server_ + ":" + root_port_;
    TEE_CHECK_RETURN(service_impl_.AecsSyncFromRemote(endpoint));
    TEE_LOG_INFO("Sync identity Successfully!");
  }

  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace aecs
