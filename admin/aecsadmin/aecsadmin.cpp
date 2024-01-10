#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "gflags/gflags.h"

#include "aecs/error.h"

#include "aecsadmin/aecsadmin_grpc_client.h"
#include "common/kubeconfig_parser.h"

#include "./aecs_admin.pb.h"

using aecs::client::AecsAdminClient;

static const char kVersion[] = "v1";
static const char kUsage[] =
    "aecsadmin --action <sub-command> [option-flags ...]\n"
    "\nSub Commands:\n"
    "\tregister      Register a enclave service\n"
    "\tunregister    Unregister a enclave service and remove all\n"
    "\tlist          List all enclave service names\n"
    "\tlistsecret    List all the trusted application bound secrets\n"
    "\tdelsecret     Destroy a trustd application bound secret by name\n"
    "\tprovision     Provision AECS, such as OSS authentication information\n"
    "\tsync          Sync secret from another remote AECS runtime instance\n"
    "\tbackup        Backup the identity key into the storage\n"
    "\tbackuplist    List all identity key backup or speical one\n"
    "\tbackupdel     Delete identity key backup by name\n"
    "\tstatus        Get the aecs enclave information and status\n";

// Define the command line options
DEFINE_string(action, "", "Sub command to be executed");
DEFINE_string(config, "", "AECS Administrator identity RSA private key");
DEFINE_string(service, "", "The enclave service name");
DEFINE_string(secret, "", "The trusted application bound secret name");
DEFINE_string(servicepasswordhash, "", "The password SHA256 for service");
DEFINE_string(pubkey, "", "Enclave service owner identity RSA public key");
DEFINE_string(password, "", "Password for AECS/Service administrator");
DEFINE_string(osskeyid, "", "Access key ID for ossauth sub command");
DEFINE_string(osskeysecret, "", "Access key secret for ossauth sub command");
DEFINE_string(ossbucket, "", "Bucket name for ossauth sub command");
DEFINE_string(ossendpoint, "", "Endpoint for ossauth sub command");
DEFINE_string(hostname, "", "Host name for identity backup");
DEFINE_string(endpoint, "", "Remote endpoint for sync command");

#define CHECK_FLAGS(f, m)                      \
  do {                                         \
    if (f.empty()) {                           \
      TEE_LOG_ERROR(m);                        \
      return AECS_ERROR_PARAMETER_FLAGS_EMPTT; \
    }                                          \
  } while (0)

//=============================================================
// The action handlers
//=============================================================

TeeErrorCode DoProvision(AecsAdminClient* aecs_client) {
  AecsProvisionRequest req;
  AecsProvisionResponse res;

  // For localfs storage, oss secrets are optional
  // CHECK_FLAGS(FLAGS_osskeyid, "Empty OSS access key id");
  // CHECK_FLAGS(FLAGS_osskeysecret, "Empty OSS access key secret");
  // CHECK_FLAGS(FLAGS_ossbucket, "Empty OSS bucket name");
  // CHECK_FLAGS(FLAGS_ossendpoint, "Empty OSS endpoint");
  // CHECK_FLAGS(FLAGS_hostname, "Empty host name");

  req.mutable_auth()->set_access_key_id(FLAGS_osskeyid);
  req.mutable_auth()->set_access_key_secret(FLAGS_osskeysecret);
  req.mutable_auth()->set_endpoint(FLAGS_ossendpoint);
  req.mutable_auth()->set_bucket_name(FLAGS_ossbucket);
  // host_name is used for the identity key backup name in OSS
  req.set_host_name(FLAGS_hostname);
  TEE_CHECK_RETURN(aecs_client->AecsProvision(req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode DoRemoteSync(AecsAdminClient* aecs_client) {
  SyncWithRemoteAecsRequest req;
  SyncWithRemoteAecsResponse res;

  // host_name is used for the identity key backup name in OSS
  CHECK_FLAGS(FLAGS_endpoint, "Empty remote endpoint");
  req.set_remote_endpoint(FLAGS_endpoint);

  TEE_CHECK_RETURN(aecs_client->SyncWithRemoteAecs(req, &res));

  printf("[AECS Status] %s", res.status_str().c_str());

  return TEE_SUCCESS;
}

TeeErrorCode DoBackupIdentityKey(AecsAdminClient* aecs_client) {
  AecsBackupIdentityRequest req;
  AecsBackupIdentityResponse res;

  // host_name is used for the identity key backup name in OSS
  CHECK_FLAGS(FLAGS_hostname, "Empty host name");
  req.set_host_name(FLAGS_hostname);

  TEE_CHECK_RETURN(aecs_client->AecsBackupIdentity(req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode DoListIdentityKeyBackup(AecsAdminClient* aecs_client) {
  AecsListBackupIdentityRequest req;
  AecsListBackupIdentityResponse res;

  // host_name is used for the identity key backup name in OSS
  req.set_host_name(FLAGS_hostname);

  TEE_CHECK_RETURN(aecs_client->AecsListBackupIdentity(req, &res));

  // Simply list the json string of message
  printf("[BackupList]: %ld\n", res.results_size());
  for (int i = 0; i < res.results_size(); i++) {
    printf("IdentityBackupName: %s, IdentityPublicKeyHash: %s\n",
           res.results()[i].identity_backup_name().c_str(),
           res.results()[i].identity_public_key_hash().c_str());
  }
  return TEE_SUCCESS;
}

TeeErrorCode DoDeleteIdentityKeyBackup(AecsAdminClient* aecs_client) {
  AecsDeleteBackupIdentityRequest req;
  AecsDeleteBackupIdentityResponse res;

  // host_name is used for the identity key backup name in OSS
  CHECK_FLAGS(FLAGS_hostname, "Empty backup name");
  req.set_host_name(FLAGS_hostname);

  TEE_CHECK_RETURN(aecs_client->AecsDeleteBackupIdentity(req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode DoGetStatus(AecsAdminClient* aecs_client) {
  printf("[AECS Status] %s\n", aecs_client->CachedStatus().c_str());
  return TEE_SUCCESS;
}

TeeErrorCode DoRegisterEnclaveService(AecsAdminClient* aecs_client) {
  RegisterEnclaveServiceRequest req;
  RegisterEnclaveServiceResponse res;

  CHECK_FLAGS(FLAGS_service, "Empty service name");
  CHECK_FLAGS(FLAGS_pubkey, "Empty public key file name");
  // Allow empty seviceadmin password
  // CHECK_FLAGS(FLAGS_servicepasswordhash, "Empty service password hash");

  // Get enclave service public key from local file
  std::string public_key;
  TEE_CHECK_RETURN(kubetee::utils::FsReadString(FLAGS_pubkey, &public_key));

  req.set_service_name(FLAGS_service);
  req.set_service_password_hash(FLAGS_servicepasswordhash);
  req.set_service_pubkey(public_key);
  TEE_CHECK_RETURN(aecs_client->RegisterEnclaveService(req, &res));
  return TEE_SUCCESS;
}

TeeErrorCode DoUnregisterEnclaveService(AecsAdminClient* aecs_client) {
  UnregisterEnclaveServiceRequest req;
  UnregisterEnclaveServiceResponse res;

  CHECK_FLAGS(FLAGS_service, "Empty service name");
  req.set_service_name(FLAGS_service);
  TEE_CHECK_RETURN(aecs_client->UnregisterEnclaveService(req, &res));
  return TEE_SUCCESS;
}

TeeErrorCode DoListTaSecret(AecsAdminClient* aecs_client) {
  AecsListTaSecretRequest req;
  AecsListTaSecretResponse res;

  req.set_secret_name(FLAGS_secret);
  TEE_CHECK_RETURN(aecs_client->ListTaSecret(req, &res));

  // List the json string of secret spec line by line
  printf("Total secrets: %d\n", res.secrets_size());
  for (int i = 0; i < res.secrets_size(); i++) {
    std::string secret_json_str;
    PB2JSON(res.secrets()[i], &secret_json_str);
    printf("[Secret:%d] %s\n", i + 1, secret_json_str.c_str());
  }
  return TEE_SUCCESS;
}

TeeErrorCode DoDestroyTaSecret(AecsAdminClient* aecs_client) {
  AecsDestroyTaSecretRequest req;
  AecsDestroyTaSecretResponse res;

  CHECK_FLAGS(FLAGS_secret, "Empty secret name");
  req.set_secret_name(FLAGS_secret);

  TEE_CHECK_RETURN(aecs_client->DestroyTaSecret(req, &res));
  return TEE_SUCCESS;
}

TeeErrorCode DoListEnclaveService(AecsAdminClient* aecs_client) {
  ListEnclaveServiceRequest req;
  ListEnclaveServiceResponse res;

  req.set_service_name(FLAGS_service);
  TEE_CHECK_RETURN(aecs_client->ListEnclaveService(req, &res));

  // Simply list the json string of message
  std::string res_json_str;
  PB2JSON(res, &res_json_str);
  printf("Total services: %ld\n", res.services().names_size());
  printf("[Services] %s\n", res_json_str.c_str());
  return TEE_SUCCESS;
}

// Main start
int main(int argc, char** argv) {
  gflags::SetVersionString(kVersion);
  gflags::SetUsageMessage(kUsage);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Firstly, parse the kubeconfig file for the administrator
  TEE_LOG_INFO("Load kubeconfig file: %s", FLAGS_config.c_str());
  kubetee::KubeConfig conf;
  aecs::client::KubeConfigParser parser(FLAGS_config);
  TEE_CHECK_RETURN(parser.Parse(&conf));

  // Then, create the secure client connect to the server
  // to avoid to to this in each handler function.
  TEE_LOG_INFO("Connecting to %s", conf.server_endpoint().c_str());
  AecsAdminClient aecs_client(conf, FLAGS_password);
  aecs_client.GetAecsStatus();

  // Do real things for the specified sub command
  if (FLAGS_action == "register") {
    TEE_CHECK_RETURN(DoRegisterEnclaveService(&aecs_client));
  } else if (FLAGS_action == "unregister") {
    TEE_CHECK_RETURN(DoUnregisterEnclaveService(&aecs_client));
  } else if (FLAGS_action == "list") {
    TEE_CHECK_RETURN(DoListEnclaveService(&aecs_client));
  } else if (FLAGS_action == "listsecret") {
    TEE_CHECK_RETURN(DoListTaSecret(&aecs_client));
  } else if (FLAGS_action == "delsecret") {
    TEE_CHECK_RETURN(DoDestroyTaSecret(&aecs_client));
  } else if (FLAGS_action == "provision") {
    TEE_CHECK_RETURN(DoProvision(&aecs_client));
  } else if (FLAGS_action == "sync") {
    TEE_CHECK_RETURN(DoRemoteSync(&aecs_client));
  } else if (FLAGS_action == "backup") {
    TEE_CHECK_RETURN(DoBackupIdentityKey(&aecs_client));
  } else if (FLAGS_action == "backuplist") {
    TEE_CHECK_RETURN(DoListIdentityKeyBackup(&aecs_client));
  } else if (FLAGS_action == "backupdel") {
    TEE_CHECK_RETURN(DoDeleteIdentityKeyBackup(&aecs_client));
  } else if (FLAGS_action == "status") {
    TEE_CHECK_RETURN(DoGetStatus(&aecs_client));
  } else {
    TEE_LOG_ERROR("Invalid action: %s", FLAGS_action.c_str());
    return AECS_ERROR_PARAMETER_INVALID_ACTION;
  }

  return 0;
}
