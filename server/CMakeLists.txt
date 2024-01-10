# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)
set(AECS_PROTO_FILES
    ${UAL_TOP_DIR}/proto/attestation.proto
    ${UAL_TOP_DIR}/proto/crypto.proto
    ${AECS_TOP_DIR}/proto/aecs.proto
    ${AECS_TOP_DIR}/proto/aecs_service.proto
)
GRPC_GENERATE_CPP(
    AECS_GRPC_SRCS
    AECS_GRPC_HDRS
    ${CMAKE_BINARY_DIR}
    ${AECS_PROTO_FILES}
)

# Generate the trusted targets
set(AECS_LDS ${ENCLAVE_LDS})
set(AECS_KEY ${ENCLAVE_KEY})
set(AECS_EDL ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.edl)
set(AECS_XML ${ENCLAVE_XML})
set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave
    ${ENCLAVE_EDL_SEARCH_PATHS_UA}
)

file(GLOB AECS_TRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/trusted/*.cpp)
set(AECS_TLIBS aecs_tprotobuf ${UAL_T_LIBS_NAME})
set(AECS_TSRCS
    ${AECS_TRUSTED_SRCS}
)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${AECS_TOP_DIR}/include
    ${UAL_TOP_DIR}/include
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
    ${SGXSSL_INCLUDE_DIR}
)
enclave_sign(
    ${AECSENCLAVE}
    KEY ${AECS_KEY}
    CONFIG ${AECS_XML}
)

# Generate the untrusted targets
file(GLOB AECS_COMMON_UNTRUSTED_SRCS ${AECS_TOP_DIR}/common/untrusted/*.cpp)
file(GLOB AECS_UNTRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/untrusted/*.cpp)
set(AECS_USRCS
    ${AECS_COMMON_UNTRUSTED_SRCS}
    ${AECS_UNTRUSTED_SRCS}
    ${AECS_GRPC_SRCS})
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${AECS_TOP_DIR}/include
    ${UAL_TOP_DIR}/include
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
    -lprotobuf -lgpr
    gRPC::grpc++_reflection
    -Wl,--start-group -laecs_uprotobuf -lua_ugrpc ${UAL_LIBS_LINK} -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64:/usr/lib/x86_64-linux-gnu:${SGX_LIBRARY_DIR}
)
add_dependencies(${AECSAPP} aecs_uprotobuf ua_ugrpc ${UAL_LIBS_NAME})
