cmake_minimum_required(VERSION 3.5)
project(kubetee-aecs)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread")

set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)
link_directories(${LIBRARY_OUTPUT_PATH})

set(AECS_TOP_DIR ${CMAKE_SOURCE_DIR})
set(AECS_BINARY_DIR ${CMAKE_BINARY_DIR})
set(UA_TOP_DIR ${AECS_TOP_DIR}/third_party/unified_attestation)
set(UAL_TOP_DIR ${UA_TOP_DIR}/ual)
list(APPEND CMAKE_MODULE_PATH ${UA_TOP_DIR}/cmake)
include(${UA_TOP_DIR}/cmake/CheckTeeEnv.cmake)

if(HAS_TEE STREQUAL "ON")
    # Common settings for add_enclave_library
    set(ENCLAVE_KEY ${UAL_TOP_DIR}/enclave/enclave_private.pem)
    set(ENCLAVE_LDS ${UAL_TOP_DIR}/enclave/lds/enclave_${TEE_TYPE}.lds)
    set(ENCLAVE_XML ${UAL_TOP_DIR}/enclave/config/enclave.config.${BUILD_MODE}.xml)
    set(ENCLAVE_EDL_SEARCH_PATHS_UA
        ${UAL_TOP_DIR}/enclave/edl
        ${UAL_TOP_DIR}/include
        ${SGXSSL_INCLUDE_DIR}
    )
endif()

# How to use UAL libraries when ENVTYPE=SGXSDK, using merged ual lib
set(UAL_U_LIBS_DEPS -lcurl -lprotobuf -lssl -lcrypto)
if(TEE_TYPE STREQUAL "SGX2")
    list(APPEND UAL_U_LIBS_DEPS -lsgx_dcap_ql -lsgx_quote_ex)
endif()
SET(UAL_LIBS_LINK -lual_u ${UAL_U_LIBS_DEPS})
SET(UAL_LIBS_NAME ual_u)
SET(UAL_T_LIBS_LINK -lual_t)
SET(UAL_T_LIBS_NAME ual_t)
message(STATUS "UAL_LIBS_NAME: ${UAL_LIBS_LINK}")

# Build the unified attestation libraries
add_subdirectory(${UAL_TOP_DIR})

# Build the third party libraries
add_subdirectory(third_party/gflags)
add_subdirectory(third_party/yaml-cpp)

# Build the AECS server
add_subdirectory(proto)
add_subdirectory(server)
add_subdirectory(server/storage_backend_fs)

# Build the AECS administrator tools
add_subdirectory(admin)
# Build the AECS client example
if(ENV_TYPE STREQUAL "SGXSDK")
add_subdirectory(client/cpp_sdk)
else()
add_subdirectory(client/cpp_oclcum)
endif()
