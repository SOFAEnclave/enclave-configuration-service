# Generate the storage back-end library
set(STORAGE_BACKEND_LIB storage_backend)
file(GLOB STORAGE_BACKEND_CPPSRCS ${CMAKE_CURRENT_SOURCE_DIR}/${_target}/*.cpp)
add_library(${STORAGE_BACKEND_LIB} SHARED
    ${STORAGE_BACKEND_CPPSRCS}
)
target_include_directories(${STORAGE_BACKEND_LIB} PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${AECS_TOP_DIR}/include
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
)
target_link_libraries(
    ${STORAGE_BACKEND_LIB}
    -fPIC
    -lprotobuf -laecs_uprotobuf
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib:/usr/local/lib64
)
add_dependencies(${STORAGE_BACKEND_LIB} aecs_uprotobuf)
