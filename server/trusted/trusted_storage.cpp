#include <string>

#include "tee/common/envelope.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

#include "tee/trusted/trusted_instance.h"
#include "tee/trusted/trusted_pbcall.h"

#include "./aecs.pb.h"
#include "trusted/trusted_storage.h"

namespace tee {
namespace trusted {

TeeErrorCode StorageTrustedBridge::SetAuth(const tee::StorageAuth& auth) {
  if (!auth_.access_key_id().empty() || !auth_.access_key_secret().empty() ||
      !auth_.endpoint().empty() || !auth_.bucket_name().empty()) {
    ELOG_ERROR("Try to update the existed storage authentication information");
    return TEE_ERROR_UNEXPECTED;
  }
#if 0  // TODO(junxian) Get the storage backend type for check or not
  if (auth.access_key_id().empty() || auth.access_key_secret().empty() ||
      auth.endpoint().empty() || auth.bucket_name().empty()) {
    ELOG_ERROR("The storage authentication information is not completed");
    return TEE_ERROR_PARAMETERS;
  }
#endif

  ELOG_INFO("storage authentication information is imported");
  auth_.CopyFrom(auth);
  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::StorageCreate(const std::string& name,
                                                 const std::string& value,
                                                 const bool force_create,
                                                 const bool identity_encrypt) {
  std::string value_str;
  if (identity_encrypt) {
    // Envelop encrypt the value by identity public key
    tee::DigitalEnvelopeEncrypted value_enc;
    tee::common::DigitalEnvelope env(name);
    tee::KeyPair& identity = TeeInstance::GetInstance().GetIdentity();
    TEE_CHECK_RETURN(env.Encrypt(identity.public_key(), value, &value_enc));
    PB_SERIALIZE(value_enc, &value_str);
  } else {
    // write the plain value string
    value_str = value;
  }

  // Write the value string
  tee::StorageCreateRequest req;
  tee::StorageCreateResponse res;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_name(name);
  req.set_value(value_str);
  req.set_force(force_create);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageCreate", req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::Create(const std::string& name,
                                          const std::string& value,
                                          const bool identity_encrypt) {
  TEE_CHECK_RETURN(StorageCreate(name, value, false, identity_encrypt));
  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::Update(const std::string& name,
                                          const std::string& value,
                                          const bool identity_encrypt) {
  TEE_CHECK_RETURN(StorageCreate(name, value, true, identity_encrypt));
  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::Delete(const std::string& prefix) {
  tee::StorageDeleteRequest req;
  tee::StorageDeleteResponse res;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_prefix(prefix);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageDelete", req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::GetValue(const std::string& name,
                                            std::string* value,
                                            const bool identity_decrypt) {
  // Read the encrypted value
  tee::StorageGetValueRequest req;
  tee::StorageGetValueResponse res;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_name(name);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageGetValue", req, &res));

  if (identity_decrypt) {
    // Envelop decrypt the value by identity private key
    tee::DigitalEnvelopeEncrypted value_enc;
    PB_PARSE(value_enc, res.value());
    tee::common::DigitalEnvelope env(name);
    tee::KeyPair& identity = TeeInstance::GetInstance().GetIdentity();
    TEE_CHECK_RETURN(env.Decrypt(identity.private_key(), value_enc, value));
  } else {
    // Return the value directly
    value->assign(res.value());
  }
  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::ListAll(const std::string& pattern,
                                           tee::StorageListAllResponse* res) {
  tee::StorageListAllRequest req;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_pattern(pattern);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageListAll", req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::CheckExist(const std::string& name,
                                              bool* exist) {
  tee::StorageCheckExistRequest req;
  tee::StorageCheckExistResponse res;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_name(name);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageCheckExist", req, &res));

  *exist = res.exist();
  return TEE_SUCCESS;
}

}  // namespace trusted
}  // namespace tee
