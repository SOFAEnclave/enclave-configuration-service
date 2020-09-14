# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)
set(AECS_PROTO_FILES
    ${TEE_TOP_DIR}/proto/kubetee.proto
    ${AECS_TOP_DIR}/proto/aecs.proto
    ${AECS_TOP_DIR}/proto/aecs_service.proto
    ${AECS_TOP_DIR}/proto/aecs_admin.proto
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

# Building client side CLI tool for aecsadmin and serviceadmin
foreach(_target aecsadmin serviceadmin)
    message(STATUS "==== Building ${_target}")
    file(GLOB ${_target}_CPPSRCS ${CMAKE_CURRENT_SOURCE_DIR}/${_target}/*.cpp)
    add_executable(${_target}
        ${AECS_PROTO_SRCS}
        ${AECS_GRPC_SRCS}
        ${${_target}_CPPSRCS}
        ${CMAKE_CURRENT_SOURCE_DIR}/common/kubeconfig_parser.cpp
    )
    target_include_directories(${_target} PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AECS_TOP_DIR}
        ${AECS_BINARY_DIR}/third_party/gflags/include
        ${AECS_TOP_DIR}/third_party/yaml-cpp/include
        ${TEE_TOP_DIR}/sdk/include
    )
    target_link_libraries(${_target}
        -L${LIBRARY_OUTPUT_PATH}
        protobuf::libprotobuf gRPC::grpc++_reflection
        gflags_nothreads yaml-cpp
        challenger ukubetee
    )
    add_dependencies(${_target} gflags yaml-cpp ukubetee challenger)
endforeach(_target)
