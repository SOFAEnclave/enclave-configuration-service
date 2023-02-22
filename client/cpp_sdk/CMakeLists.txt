# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)
set(AECS_PROTO_FILES
    ${UAL_TOP_DIR}/proto/attestation.proto
    ${UAL_TOP_DIR}/proto/crypto.proto
    ${AECS_TOP_DIR}/proto/aecs.proto
    ${AECS_TOP_DIR}/proto/aecs_service.proto
)
PROTOBUF_GENERATE_CPP(
    AECS_PROTO_SRCS
    AECS_PROTO_HDRS
    ${CMAKE_BINARY_DIR}
    ${AECS_PROTO_FILES}
)
GRPC_GENERATE_CPP(
    AECS_GRPC_SRCS
    AECS_GRPC_HDRS
    ${CMAKE_BINARY_DIR}
    ${AECS_PROTO_FILES}
)

# Generate the trusted targets
set(AECS_CLIENT_LDS ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.lds)
set(AECS_CLIENT_KEY ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave_private.pem)
set(AECS_CLIENT_EDL ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.edl)
if(BUILD_MODE STREQUAL "Release")
    set(AECS_CLIENT_XML ${CMAKE_SOURCE_DIR}/deployment/sign/enclave.config.${TEE_TYPE}.xml)
else()
    set(AECS_CLIENT_XML ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.config.xml)
endif()
set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave
    ${ENCLAVE_EDL_SEARCH_PATHS_UA}
)

file(GLOB AECS_CLIENT_TRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/trusted/*.cpp)
set(AECS_CLIENT_TLIBS ${UAL_T_LIBS_NAME})
set(AECS_CLIENT_TSRCS
    ${AECS_CLIENT_TRUSTED_SRCS}
    ${CMAKE_BINARY_DIR}/aecs.pb.cc
)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${AECS_TOP_DIR}/include
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
)

set(AECS_CLIENT_ENCLAVE aecs_client_test_enclave)
add_enclave_library(
    ${AECS_CLIENT_ENCLAVE}
    SRCS ${AECS_CLIENT_TSRCS}
    TRUSTED_LIBS ${AECS_CLIENT_TLIBS}
    EDL ${AECS_CLIENT_EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
    LDSCRIPT ${AECS_CLIENT_LDS}
)
target_include_directories(
    ${AECS_CLIENT_ENCLAVE} PRIVATE
    ${SGXSSL_INCLUDE_DIR}
)
enclave_sign(
    ${AECS_CLIENT_ENCLAVE}
    KEY ${AECS_CLIENT_KEY}
    CONFIG ${AECS_CLIENT_XML}
)

# Generate the untrusted targets
file(GLOB AECS_CLIENT_COMMON_UNTRUSTED_SRCS ${AECS_TOP_DIR}/common/untrusted/*.cpp)
file(GLOB AECS_CLIENT_UNTRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/untrusted/*.cpp)
set(AECS_CLIENT_USRCS
    ${AECS_CLIENT_COMMON_UNTRUSTED_SRCS}
    ${AECS_CLIENT_UNTRUSTED_SRCS}
    ${AECS_PROTO_SRCS}
    ${AECS_GRPC_SRCS}
)
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${AECS_BINARY_DIR}/third_party/gflags/include
    ${AECS_TOP_DIR}/include
    ${UAL_TOP_DIR}/include
)
set(AECS_CLIENT_APP aecs_client_test_service)
add_untrusted_executable(
    ${AECS_CLIENT_APP}
    SRCS ${AECS_CLIENT_USRCS}
    EDL ${AECS_CLIENT_EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
)
target_link_libraries(
    ${AECS_CLIENT_APP}
    -lprotobuf -lgflags_nothreads
    gRPC::grpc++_reflection
    -Wl,--start-group -lua_ugrpc ${UAL_LIBS_LINK} -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)
add_dependencies(${AECS_CLIENT_APP} ua_ugrpc ${UAL_LIBS_NAME})
