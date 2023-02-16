#ifndef INCLUDE_AECS_UNTRUSTED_ENCLAVE_H_
#define INCLUDE_AECS_UNTRUSTED_ENCLAVE_H_

#include <map>
#include <memory>
#include <string>

// Header files in unified attestation
#include "unified_attestation/ua_untrusted.h"

// The AECS untrusted enclave instance name
constexpr char kAecsServerName[] = "AecsServer";

namespace aecs {
namespace untrusted {

// EnclaveInstance create one class instance for each enclave instance.
// enclave instance include untrusted part and trusted part, the trusted
// part is managed by TeeInstance
class EnclaveInstance {
 public:
  // Create the normal enclave by name
  EnclaveInstance(const std::string& name, const std::string& filename);
  ~EnclaveInstance();

  // Initialize method creates the identity RSA key pair inside enclave
  // and also prepare the enclave information for generating quote later
  TeeErrorCode Initialize();

  // Initialize method with the cached identity RSA key pair.
  TeeErrorCode Initialize(const std::string& identity_sealed);

  // Generator RA report by the related AttestationGenerator
  TeeErrorCode CreateRaReport(bool use_cache = true);

  // Run ECall Function based on serialized protobuf message parameters
  TeeErrorCode TeeRun(const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response);

  // Get the enclave EID, usually it's should be greater than 2
  const std::string& GetEnclaveID() {
    return tee_identity_;
  }

  // Get the enclave name, the name should be unique, otherwise maybe the
  // wrong enclave instance will be found when GetEnclaveByName(name)
  std::string GetEnclaveName() {
    return enclave_name_;
  }

  // Get the enclave identity public key, it should not be empty after
  // enclave instance is successfully initialized.
  std::string GetPublicKey() {
    return report_.pem_public_key();
  }

  // Get the enclave information handler
  kubetee::UnifiedAttestationAttributes& GetEnclaveInfo() {
    return enclave_info_;
  }

  // Get the local information handler
  kubetee::UnifiedAttestationAuthReport& GetLocalAuthReport() {
    return report_;
  }

 private:
  std::string tee_identity_;
  std::string enclave_name_;
  kubetee::UnifiedAttestationAttributes enclave_info_;
  kubetee::UnifiedAttestationAuthReport report_;
};

typedef std::shared_ptr<EnclaveInstance> EnclaveInstancePtr;
typedef std::map<std::string, EnclaveInstancePtr> EnclaveInstancesMap;

// EnclavesManager is to manage enclaves instances together
class EnclavesManager {
 public:
  // Gets the singleton enclave manager instance handler
  static EnclavesManager& GetInstance() {
    static EnclavesManager instance_;
    return instance_;
  }

  /// Create a new enclave instance and return the handler which points to it
  ///
  /// @param name specifies the name of this enclave instance
  /// @param filename specifies the name of the enclave so file
  ///
  /// @return EnclaveInstance pointer, nullptr on fail
  EnclaveInstance* CreateEnclave(const std::string& name,
                                 const std::string& filename);

  /// @brief Load encrypted enclave so file and create the enclave instance
  ///
  /// This is for the Protected Code Loader mode enclave work flow.
  /// @param name specifies the name of this enclave instance
  /// @param filename specifies the name of the enclave so file
  /// @param sealed_key specifies the key to decrypt encrypted enclave file
  ///
  /// @return TeeErrorCode type error code, TEE_SUCCESS or other error
  EnclaveInstance* CreateEnclave(const std::string& name,
                                 const std::string& filename,
                                 const uint8_t* sealed_key);

  /// @brief Simply destroy the enclave instance via its EID
  ///
  /// @param enclave specifies the pointer of the enclave instance
  ///
  /// @return TeeErrorCode type error code, TEE_SUCCESS or other error
  TeeErrorCode DestroyEnclave(EnclaveInstance* enclave);

  /// @brief Get the enclave instance pointer via its identity
  ///
  /// @param eid specifies the successfully created enclave instance ID
  ///
  /// @return The pointer to EnclaveInstance or nullptr
  EnclaveInstance* GetEnclaveById(const std::string& tee_identity);

  /// @brief Get the enclave instance pointer via its name
  ///
  /// @param name specifies the enclave name
  ///
  /// @return The pointer to EnclaveInstance or nullptr
  EnclaveInstance* GetEnclaveByName(const std::string& name);

 private:
  // Hide construction functions
  EnclavesManager() {
    is_functions_registed_ = false;
  }
  EnclavesManager(const EnclavesManager&);
  void operator=(EnclavesManager const&);

  EnclaveInstancesMap enclaves_;
  bool is_functions_registed_;
};

}  // namespace untrusted
}  // namespace aecs

using aecs::untrusted::EnclaveInstance;
using aecs::untrusted::EnclavesManager;

#endif  // INCLUDE_AECS_UNTRUSTED_ENCLAVE_H_
