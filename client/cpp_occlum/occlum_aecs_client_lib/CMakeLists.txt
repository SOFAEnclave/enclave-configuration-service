# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)
set(AECS_PROTO_FILES
  ${UAL_TOP_DIR}/proto/attestation.proto
  ${UAL_TOP_DIR}/proto/crypto.proto
  ${AECS_TOP_DIR}/proto/aecs.proto
  ${AECS_TOP_DIR}/proto/aecs_admin.proto
  ${AECS_TOP_DIR}/proto/aecs_service.proto
)
set(AECS_SECRET_POLICY_PARSER
  ${AECS_TOP_DIR}/admin/serviceadmin/serviceadmin_secret_policy.cpp
)
PROTOBUF_GENERATE_CPP(AECS_PROTO_SRCS AECS_PROTO_HDRS ${CMAKE_BINARY_DIR} ${AECS_PROTO_FILES})
GRPC_GENERATE_CPP(AECS_GRPC_SRCS AECS_GRPC_HDRS ${CMAKE_BINARY_DIR} ${AECS_PROTO_FILES})

# Generate the library
set(GRPC_CLIENT_SRCS
  ${UAL_TOP_DIR}/grpc/untrusted_grpc_client.cpp
  ${AECS_TOP_DIR}/client/cpp_sdk/untrusted/untrusted_aecs_client.cpp
)
file(GLOB LOCAL_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
set(LIB_SRCS
  ${GRPC_CLIENT_SRCS}
  ${AECS_SECRET_POLICY_PARSER}
  ${LOCAL_SRCS}
  ${AECS_PROTO_SRCS}
  ${AECS_GRPC_SRCS}
)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${AECS_TOP_DIR}/include
  ${AECS_TOP_DIR}/admin
  ${AECS_TOP_DIR}/client/cpp_sdk
  ${AECS_TOP_DIR}/third_party/yaml-cpp/include
  ${CMAKE_BINARY_DIR}/gflags/include
  ${UAL_TOP_DIR}/include
  ${UAL_TOP_DIR}/include/sgx
)

set(AECS_CLIENT_LIB aecs_client)
add_library(
  ${AECS_CLIENT_LIB} SHARED
  ${LIB_SRCS}
)
target_link_libraries(
  ${AECS_CLIENT_LIB}
  -L/usr/local/occlum/x86_64-linux-gnu/lib
  yaml-cpp
  -Wl,--start-group ${${UAL_LIBS_LINK}} -lprotobuf -lcares_static -laddress_sorting -lgpr -lgrpc -lgrpc++ -lgrpc++_reflection -Wl,--end-group
  -Wl,-rpath=/lib
)
add_dependencies(${AECS_CLIENT_LIB} yaml-cpp ${UAL_LIBS_NAME})

# Generate the test application
set(APP aecs_client_get_secret)
file(GLOB APP_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_executable(${APP} ${APP_SRCS})
target_link_libraries(
  ${APP}
  -L/usr/local/occlum/x86_64-linux-gnu/lib
  -lgflags_nothreads
  -Wl,--start-group -l${AECS_CLIENT_LIB} ${UAL_LIBS_LINK} -lz -lgrpc++ -lgrpc++_reflection -Wl,--end-group
  -Wl,-rpath=/lib
)
add_dependencies(${APP} gflags ${AECS_CLIENT_LIB} ${UAL_LIBS_NAME})