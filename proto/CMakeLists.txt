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

# Generate the untrusted targets
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${AECS_TOP_DIR}/include
    ${UAL_TOP_DIR}/include
)
set(AECS_TPROTOBUF aecs_tprotobuf)
add_trusted_library_without_edl(
    ${AECS_TPROTOBUF}
    SRCS ${AECS_PROTO_SRCS}
)
target_link_libraries(
    ${AECS_TPROTOBUF}
    ${UAL_T_LIBS_LINK}
)
add_dependencies(${AECS_TPROTOBUF} ${UAL_T_LIBS_NAME})

# Generate the untrusted targets
set(AECS_UPROTOBUF aecs_uprotobuf)
add_library(
    ${AECS_UPROTOBUF}
    ${AECS_PROTO_SRCS}
)
target_link_libraries(
    ${AECS_UPROTOBUF}
    -lprotobuf
)
