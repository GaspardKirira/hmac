cmake_minimum_required(VERSION 3.20)
project(hmac LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(hmac INTERFACE)
add_library(hmac::hmac ALIAS hmac)

target_include_directories(hmac INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if (MSVC)
  target_compile_options(hmac INTERFACE /W4 /permissive-)
else()
  target_compile_options(hmac INTERFACE -Wall -Wextra -Wpedantic)
endif()

# --- Vix deps (hashing) ---
include(.vix/vix_deps.cmake)
target_link_libraries(hmac INTERFACE gaspardkirira::hashing)

include(CTest)
enable_testing()

add_executable(hmac_basic_test tests/test_basic.cpp)
target_link_libraries(hmac_basic_test PRIVATE hmac::hmac)
add_test(NAME hmac.basic COMMAND hmac_basic_test)
