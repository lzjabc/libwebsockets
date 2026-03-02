cmake_minimum_required(VERSION 3.10)
project(test-x509-consistency C)

set(CMAKE_C_STANDARD 99)

add_executable(test-x509-consistency test-x509-consistency.c)

target_include_directories(test-x509-consistency PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_BINARY_DIR}/include
)

target_link_libraries(test-x509-consistency websockets)
