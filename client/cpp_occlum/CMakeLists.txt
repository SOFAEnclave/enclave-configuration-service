cmake_minimum_required(VERSION 3.5)
project(OCCLUM-AECS-CLIENT-LIB)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread")

set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)

set(PROJECT_TOP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(AECS_TOP_DIR ${PROJECT_TOP_DIR})
set(UA_TOP_DIR ${AECS_TOP_DIR}/third_party/unified_attestation)
set(UAL_TOP_DIR ${UA_TOP_DIR}/ual)
list(APPEND CMAKE_MODULE_PATH ${UA_TOP_DIR}/cmake)
include(${UA_TOP_DIR}/cmake/CheckTeeEnv.cmake)

# For Occlum environment
set(ENV_TYPE "OCCLUM")

# Support to verify the AECS server report in SIM mode
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSGX_MODE_${SGX_MODE}")

# Set the compiler for occlum programming environment.
if(OCCLUM_LIBC STREQUAL "musl")
    message(STATUS "Using musl")
    set(OCCLUM_INSTALLDIR "/usr/local/occlum/x86_64-linux-musl")
    set(OCCLUM_BINDIR "/usr/local/occlum/bin")
    set(CMAKE_C_COMPILER ${OCCLUM_BINDIR}/occlum-gcc)
    set(CMAKE_CXX_COMPILER ${OCCLUM_BINDIR}/occlum-g++)
else()
    message(STATUS "Using glibc")
    set(OCCLUM_INSTALLDIR "/usr/local/occlum/x86_64-linux-gnu")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -pie")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -pie")
endif()
set(OPENSSL_INC_DIR "${OCCLUM_INSTALLDIR}/include")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${OCCLUM_INSTALLDIR}/include")
set(CMAKE_PREFIX_PATH ${OCCLUM_INSTALLDIR})
link_directories(${LIBRARY_OUTPUT_PATH} ${OCCLUM_INSTALLDIR}/lib)

# For sgx verification source code
include_directories(${UAL_TOP_DIR}/include/sgx)

# How to use UAL
SET(UAL_LIBS_LINK -lual -lprotobuf -lcurl -lssl -lcrypto)
SET(UAL_LIBS_NAME ual)

# Only build the required libraries for aecs_client
add_subdirectory(${UAL_TOP_DIR}/cmake/ual_untrusted ${CMAKE_BINARY_DIR}/ual)
add_subdirectory(occlum_aecs_client_lib)
