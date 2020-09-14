set(SGXSSL_LIB /opt/intel/sgxssl/lib64)
set(SGXSSL_INC /opt/intel/sgxssl/include)

# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)
set(AECS_PROTO_FILES
    ${TEE_TOP_DIR}/proto/kubetee.proto
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
set(AECS_LDS ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.lds)
set(AECS_KEY ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave_private.pem)
set(AECS_EDL ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.edl)
if(SGX_MODE STREQUAL "Release")
    set(AECS_XML ${AECS_TOP_DIR}/deployment/conf/enclave.config.release.xml)
else()
    set(AECS_XML ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.config.xml)
endif()
set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave
    ${TEE_TOP_DIR}/sdk/edl
    ${TEE_TOP_DIR}/sdk/include
    ${SGXSSL_INC}
)

file(GLOB AECS_TRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/trusted/*.cpp)
set(AECS_TLIBS tkubetee tprotobuf)
set(AECS_TSRCS
    ${AECS_TRUSTED_SRCS}
    ${CMAKE_BINARY_DIR}/kubetee.pb.cc
    ${CMAKE_BINARY_DIR}/aecs.pb.cc
)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${TEE_TOP_DIR}/sdk
    ${TEE_TOP_DIR}/sdk/include
    ${TEE_TOP_DIR}/third_party/protobuf-cpp/src/
)

set(AECSENCLAVE aecs_enclave)
add_enclave_library(
    ${AECSENCLAVE}
    SRCS ${AECS_TSRCS}
    TRUSTED_LIBS ${AECS_TLIBS}
    EDL ${AECS_EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
    LDSCRIPT ${AECS_LDS}
)
target_include_directories(
    ${AECSENCLAVE} PRIVATE
    ${SGXSSL_INC}
)
enclave_sign(
    ${AECSENCLAVE}
    KEY ${AECS_KEY}
    CONFIG ${AECS_XML}
)

# Generate the untrusted targets
file(GLOB AECS_CPPSRCS ${CMAKE_CURRENT_SOURCE_DIR}/untrusted/*.cpp)
set(AECS_USRCS ${AECS_CPPSRCS} ${AECS_PROTO_SRCS} ${AECS_GRPC_SRCS})
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${TEE_TOP_DIR}/sdk
    ${TEE_TOP_DIR}/sdk/include
    ${TEE_TOP_DIR}/third_party/rapidjson/include
)
set(AECSAPP aecs_server)
add_untrusted_executable(
    ${AECSAPP}
    SRCS ${AECS_USRCS}
    EDL ${AECS_EDL}
    EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
)
target_link_libraries(
    ${AECSAPP}
    -L${LIBRARY_OUTPUT_PATH} -L${SGX_LIBRARY_DIR} -L${SGXSSL_LIB}
    -L/usr/lib64 -L/usr/local/lib64
    -lprotobuf
    gRPC::grpc++_reflection
    -Wl,--start-group -lukubetee -lchallenger -lsgx_usgxssl -lcrypto -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)
add_dependencies(${AECSAPP} ukubetee challenger)

