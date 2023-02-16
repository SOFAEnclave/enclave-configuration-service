#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <typeinfo>
#include <vector>

#include "unified_attestation/ua_untrusted.h"

#include "aecs/untrusted_config.h"
#include "aecs/untrusted_enclave.h"

#include "./aecs.pb.h"

namespace aecs {
namespace untrusted {

using kubetee::utils::FsReadString;
using kubetee::utils::FsWriteString;
using kubetee::attestation::ReeInstance;

EnclaveInstance::EnclaveInstance(const std::string& name,
                                 const std::string& filename) {
  // Initialize the enclave
  TEE_LOG_DEBUG("Enclave file name: %s", filename.c_str());
  kubetee::attestation::UaTeeInitParameters params;
  params.trust_application = filename;
  TeeErrorCode ret = ReeInstance::Initialize(params, &tee_identity_);
  if (ret == TEE_SUCCESS) {
    enclave_name_ = name;
    TEE_LOG_INFO("Enclave %s is created", name.c_str());
    TEE_LOG_DEBUG("Enclave identity:%s", tee_identity_.c_str());
  } else {
    TEE_LOG_ERROR("Fail to create enclave:%s, ret:0x%X", name.c_str(), ret);
  }
}

EnclaveInstance::~EnclaveInstance() {
  TeeErrorCode ret = ReeInstance::Finalize(tee_identity_);
  if (ret == TEE_SUCCESS) {
    TEE_LOG_INFO("Destroy enclave %s", enclave_name_.c_str());
    TEE_LOG_DEBUG("Enclave identity:%s", tee_identity_.c_str());
  } else {
    TEE_LOG_ERROR("Destroy enclave:%s, ret:0x%X", enclave_name_.c_str(), ret);
  }
}

TeeErrorCode EnclaveInstance::Initialize() {
  // Load sealed enclave identity keypair, it may be empty on first time.
  std::string identity_cache = AECS_CONF_STR(kAecsConfIdentityKeyCache);
  std::string identity_file =
      AECS_CONF_STR(kAecsConfIdentityKeyCacheFile) + "." + enclave_name_;
  std::string hex_identity_sealed;
  if (identity_cache == kConfValueEnable) {
    TeeErrorCode ret = FsReadString(identity_file, &hex_identity_sealed);
    if (ret != TEE_SUCCESS) {
      TEE_LOG_INFO("There is no cached identity key pair");
    } else {
      TEE_LOG_INFO("It's to use cached identity key pair");
    }
  }

  TEE_CHECK_RETURN(Initialize(hex_identity_sealed));
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::Initialize(
    const std::string& hex_sealed_identity) {
  if (tee_identity_.empty()) {
    TEE_LOG_ERROR("Enclave has not been created successfully");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }

  // Initialize the enclave TEE instance and create the enclave report
  kubetee::AecsInitializeEnclaveRequest req;
  kubetee::AecsInitializeEnclaveResponse res;
  req.set_hex_sealed_identity(hex_sealed_identity);
  TEE_CHECK_RETURN(TeeRun("TeeInitializeAecsEnclave", req, &res));
  std::string identity_cache = AECS_CONF_STR(kAecsConfIdentityKeyCache);
  std::string identity_file =
      AECS_CONF_STR(kAecsConfIdentityKeyCacheFile) + "." + enclave_name_;
  if ((identity_cache == kConfValueEnable) &&
      !res.enclave_hex_sealed_identity().empty()) {
    TeeErrorCode ret =
        FsWriteString(identity_file, res.enclave_hex_sealed_identity());
    if (ret != TEE_SUCCESS) {
      TEE_LOG_WARN("Fail to save new identity key pair");
      return ret;
    }
    TEE_LOG_INFO("Save new identity key pair successfully");
  }

  TEE_LOG_INFO("Enclave has been initialized successfully");
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::CreateRaReport(bool use_cache) {
  // Try load cached RA report if required by both runtime and configuration
  std::string ra_report_cache = AECS_CONF_STR(kAecsConfReportCache);
  std::string ra_report_path =
      AECS_CONF_STR(kAecsConfReportCacheFile) + "." + enclave_name_;
  std::string ra_report_str;
  if (use_cache && (ra_report_cache != kConfValueDisable)) {
    if (FsReadString(ra_report_path, &ra_report_str) == TEE_SUCCESS) {
      PB_PARSE(report_, ra_report_str);
      TEE_LOG_WARN("Reload local report successfully");
      return TEE_SUCCESS;
    }
  }

  // Fetch it from IAS if there is no local IAS report or something wrong
  kubetee::common::DataBytes hex_nonce;
  UaReportGenerationParameters report_param;
  report_param.tee_identity = tee_identity_;
#ifndef SGX_MODE_SIM
  report_param.report_type = kUaReportTypePassport;
#else
  report_param.report_type = kUaReportTypeBgcheck;
#endif
  report_param.report_hex_nonce = hex_nonce.Randomize(32).ToHexStr().GetStr();
  report_param.others.set_hex_spid(UA_CONF_STR(kUaConfIasSpid));
  TEE_CHECK_RETURN(UaGenerateAuthReport(&report_param, &report_));
  TEE_CHECK_RETURN(UaGetAuthReportAttr(report_, &enclave_info_));

  // Verify the new created report to make sure there is nothing wrong
  kubetee::UnifiedAttestationPolicy policy;
  policy.add_main_attributes()->CopyFrom(enclave_info_);
  TEE_CHECK_RETURN(UaVerifyAuthReport(report_, policy));

  // Save it in local cached file if required
  if (ra_report_cache != kConfValueDisable) {
    PB_SERIALIZE(report_, &ra_report_str);
    TEE_CHECK_RETURN(FsWriteString(ra_report_path, ra_report_str));
    TEE_LOG_INFO("Save local report successfully");
  }

  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::TeeRun(const std::string& function_name,
                                     const google::protobuf::Message& request,
                                     google::protobuf::Message* response) {
  TEE_CHECK_RETURN(ReeInstance::TeeRun(
      tee_identity_, function_name, request, response));
  return TEE_SUCCESS;
}

// EnclavesManager Functions

EnclaveInstance* EnclavesManager::CreateEnclave(const std::string& name,
                                                const std::string& filename) {
  EnclaveInstancePtr enclave(new EnclaveInstance(name, filename));
  if (enclave.get()->Initialize() != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to initialize enclave: %s", name.c_str());
    return nullptr;
  }
  enclaves_.emplace(enclave.get()->GetEnclaveID(), enclave);
  return enclave.get();
}

TeeErrorCode EnclavesManager::DestroyEnclave(EnclaveInstance* enclave) {
  const std::string& tee_identity = enclave->GetEnclaveID();
  if (enclaves_.find(tee_identity) == enclaves_.end()) {
    TEE_LOG_ERROR("Fail to find enclave %s", tee_identity.c_str());
    return TEE_ERROR_RA_NOTINITIALIZED;
  }
  enclaves_.erase(tee_identity);
  return TEE_SUCCESS;
}

EnclaveInstance* EnclavesManager::GetEnclaveById(
    const std::string& tee_identity) {
  if (enclaves_.find(tee_identity) == enclaves_.end()) {
    TEE_LOG_ERROR("Fail to find enclave %s", tee_identity.c_str());
    return nullptr;
  }
  return enclaves_[tee_identity].get();
}

EnclaveInstance* EnclavesManager::GetEnclaveByName(const std::string& name) {
  for (auto iter = enclaves_.begin(); iter != enclaves_.end(); iter++) {
    if ((iter->second).get()->GetEnclaveName() == name) {
      return (iter->second).get();
    }
  }
  TEE_LOG_ERROR("Fail to find enclave %s", name.c_str());
  return nullptr;
}

}  // namespace untrusted
}  // namespace aecs
