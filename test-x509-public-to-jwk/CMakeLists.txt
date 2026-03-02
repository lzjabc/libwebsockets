cmake_minimum_required(VERSION 3.10)
project(test-x509-public-to-jwk C)

set(CMAKE_C_STANDARD 99)

# Require JOSE support
if(NOT LWS_WITH_JOSE)
    message(FATAL_ERROR "LWS_WITH_JOSE must be enabled to build this test")
endif()

add_executable(test-x509-public-to-jwk test-x509-public-to-jwk.c)

target_include_directories(test-x509-public-to-jwk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_BINARY_DIR}/include
)

target_link_libraries(test-x509-public-to-jwk websockets)
