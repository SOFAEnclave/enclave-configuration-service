# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
set(AECS_PROTO_FILES
    ${TEE_TOP_DIR}/proto/kubetee.proto
    ${CMAKE_SOURCE_DIR}/proto/aecs.proto
    ${CMAKE_SOURCE_DIR}/proto/aecs_service.proto
)
PROTOBUF_GENERATE_CPP(
    AECS_PROTO_SRCS
    AECS_PROTO_HDRS
    ${CMAKE_BINARY_DIR}
    ${AECS_PROTO_FILES}
)

# Generate the storage back-end library
set(STORAGE_BACKEND_LIB storage_backend)
file(GLOB STORAGE_BACKEND_CPPSRCS ${CMAKE_CURRENT_SOURCE_DIR}/${_target}/*.cpp)
add_library(${STORAGE_BACKEND_LIB} SHARED
    ${STORAGE_BACKEND_CPPSRCS}
    ${AECS_PROTO_SRCS}
  )
target_include_directories(${STORAGE_BACKEND_LIB} PUBLIC
      ${CMAKE_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}
      ${CMAKE_BINARY_DIR}
      ${TEE_TOP_DIR}/sdk
      ${TEE_TOP_DIR}/sdk/include
  )
target_link_libraries(
  ${STORAGE_BACKEND_LIB}
    -fPIC
    -L${LIBRARY_OUTPUT_PATH}
    -L/usr/lib64 -L/usr/local/lib64
    -lprotobuf
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64
)

