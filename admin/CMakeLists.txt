# Generate the protobuf and grpc source and header files
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)
set(AECS_PROTO_FILES
    ${UAL_TOP_DIR}/proto/attestation.proto
    ${UAL_TOP_DIR}/proto/crypto.proto
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
        ${AECS_BINARY_DIR}/third_party/gflags/include
        ${AECS_TOP_DIR}
        ${AECS_TOP_DIR}/include
        ${AECS_TOP_DIR}/third_party/yaml-cpp/include
        ${UAL_TOP_DIR}
        ${UAL_TOP_DIR}/include
    )
    target_link_libraries(${_target}
        -L${LIBRARY_OUTPUT_PATH} -L/usr/local/lib
        -lprotobuf
        gRPC::grpc++_reflection
        gflags_nothreads yaml-cpp
        -Wl,--start-group -lua_ugrpc ${UAL_LIBS_LINK} -Wl,--end-group
        -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
    )
    add_dependencies(${_target} gflags yaml-cpp ${UAL_LIBS_NAME})
endforeach(_target)
