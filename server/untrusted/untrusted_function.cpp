#include <string>

#include "unified_attestation/ua_untrusted.h"

#include "untrusted/untrusted_function_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode RegisterUntrustedUnifiedFunctionsEx() {
  ELOG_DEBUG("Register application untrusted functions");
  ADD_UNTRUSTED_UNIFIED_FUNCTION(ReeStorageCreate);
  ADD_UNTRUSTED_UNIFIED_FUNCTION(ReeStorageDelete);
  ADD_UNTRUSTED_UNIFIED_FUNCTION(ReeStorageGetValue);
  ADD_UNTRUSTED_UNIFIED_FUNCTION(ReeStorageListAll);
  ADD_UNTRUSTED_UNIFIED_FUNCTION(ReeStorageCheckExist);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
