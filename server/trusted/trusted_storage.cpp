#include <string>

#include "unified_attestation/ua_trusted.h"

#include "aecs/error.h"
#include "trusted/trusted_storage.h"

#include "./aecs.pb.h"

using kubetee::attestation::TeeInstance;

namespace kubetee {
namespace trusted {

bool StorageTrustedBridge::CheckEmptyAuth() {
  if (auth_.access_key_id().empty() && auth_.access_key_secret().empty() ||
      auth_.endpoint().empty() && auth_.bucket_name().empty()) {
    return true;
  } else {
    return false;
  }
}

TeeErrorCode StorageTrustedBridge::SetAuth(const kubetee::StorageAuth& auth,
                                           const bool allow_update) {
  if (!CheckEmptyAuth() && !allow_update) {
    ELOG_ERROR("Try to update the existed storage authentication information");
    return AECS_ERROR_STORAGE_EXISTED_AUTH;
  }

  ELOG_INFO("storage authentication information is imported");
  auth_.CopyFrom(auth);

  // Check whether the auth value is valid when it's not empty.
  // It is not neccessary for all storage type, for example,
  // the localfs type storage don't use auth information
  if (!CheckEmptyAuth()) {
    kubetee::StorageListAllResponse res;
    // Try to access storage 3 times in case there is network issue.
    int i = 3;
    do {
      if (TEE_SUCCESS == ListAll("", &res)) {
        break;
      } else {
        ELOG_WARN("Fail to check storage auth: %d", i);
      }
    } while (i--);
    if (i <= 0) {
      auth_.Clear();
      return AECS_ERROR_STORAGE_AUTH_NOT_VALID;
    }
  }

  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::StorageCreate(const std::string& name,
                                                 const std::string& value,
                                                 const bool force_create,
                                                 const bool identity_encrypt) {
  std::string value_str;
  if (identity_encrypt) {
    // Envelop encrypt the value by identity public key
    kubetee::DigitalEnvelopeEncrypted value_enc;
    kubetee::common::DigitalEnvelope env(name);
    TeeInstance& ti = TeeInstance::GetInstance();
    const kubetee::AsymmetricKeyPair& identity = ti.GetIdentity();
    TEE_CHECK_RETURN(env.Encrypt(identity.public_key(), value, &value_enc));
    PB_SERIALIZE(value_enc, &value_str);
  } else {
    // write the plain value string
    value_str = value;
  }

  // Write the value string
  kubetee::StorageCreateRequest req;
  kubetee::StorageCreateResponse res;
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

TeeErrorCode StorageTrustedBridge::Delete(const std::string& name,
                                          const bool is_prefix) {
  kubetee::StorageDeleteRequest req;
  kubetee::StorageDeleteResponse res;
  req.mutable_auth()->CopyFrom(auth_);
  if (is_prefix) {
    req.set_prefix(name);
  } else {
    req.set_name(name);
  }
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageDelete", req, &res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::GetValue(const std::string& name,
                                            std::string* value,
                                            const bool identity_decrypt) {
  // Read the encrypted value
  kubetee::StorageGetValueRequest req;
  kubetee::StorageGetValueResponse res;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_name(name);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageGetValue", req, &res));

  if (identity_decrypt) {
    // Envelop decrypt the value by identity private key
    kubetee::DigitalEnvelopeEncrypted value_enc;
    PB_PARSE(value_enc, res.value());
    kubetee::common::DigitalEnvelope env(name);
    const kubetee::AsymmetricKeyPair& identity = ti.GetIdentity();
    TEE_CHECK_RETURN(env.Decrypt(identity.private_key(), value_enc, value));
  } else {
    // Return the value directly
    value->assign(res.value());
  }
  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::ListAll(
    const std::string& prefix, kubetee::StorageListAllResponse* res) {
  kubetee::StorageListAllRequest req;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_prefix(prefix);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageListAll", req, res));

  return TEE_SUCCESS;
}

TeeErrorCode StorageTrustedBridge::CheckExist(const std::string& name,
                                              bool* exist) {
  kubetee::StorageCheckExistRequest req;
  kubetee::StorageCheckExistResponse res;
  req.mutable_auth()->CopyFrom(auth_);
  req.set_name(name);
  TeeInstance& ti = TeeInstance::GetInstance();
  TEE_CHECK_RETURN(ti.ReeRun("ReeStorageCheckExist", req, &res));

  *exist = res.exist();
  return TEE_SUCCESS;
}

}  // namespace trusted
}  // namespace kubetee
