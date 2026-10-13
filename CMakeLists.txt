cmake_minimum_required(VERSION 3.20)
project(kernauth_sdk VERSION 0.4.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# CMake 4 rejects projects that declare a minimum older than 3.5. nlohmann/json 3.11.3 does.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

FetchContent_Declare(Sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG 9b2848dfc1b917a9410f0de9d81059b26cbfaa8d
  GIT_SUBMODULES libsodium
  GIT_SUBMODULES_RECURSE TRUE)
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Sodium)

FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
  GIT_SHALLOW TRUE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)

set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(HTTP_ONLY ON CACHE BOOL "" FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)
set(USE_LIBIDN2 OFF CACHE BOOL "" FORCE)
set(CURL_ZLIB OFF CACHE BOOL "" FORCE)
set(CURL_BROTLI OFF CACHE BOOL "" FORCE)
set(CURL_ZSTD OFF CACHE BOOL "" FORCE)
set(ENABLE_CURL_MANUAL OFF CACHE BOOL "" FORCE)
set(BUILD_LIBCURL_DOCS OFF CACHE BOOL "" FORCE)
set(BUILD_MISC_DOCS OFF CACHE BOOL "" FORCE)
set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
if(WIN32)
  set(CURL_ENABLE_SSL ON CACHE BOOL "" FORCE)
  set(CURL_USE_SCHANNEL ON CACHE BOOL "" FORCE)
  set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
else()
  set(CURL_ENABLE_SSL OFF CACHE BOOL "" FORCE)
  set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
  set(CURL_USE_SCHANNEL OFF CACHE BOOL "" FORCE)
endif()

FetchContent_Declare(curl
  GIT_REPOSITORY https://github.com/curl/curl.git
  GIT_TAG curl-8_17_0
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(curl)

if(NOT TARGET sodium)
  message(FATAL_ERROR "libsodium target 'sodium' was not created. The SDK requires libsodium and does not skip it.")
endif()
if(NOT TARGET CURL::libcurl)
  message(FATAL_ERROR "libcurl target 'CURL::libcurl' was not created. The console example requires libcurl.")
endif()
if(NOT TARGET nlohmann_json::nlohmann_json)
  message(FATAL_ERROR "nlohmann_json::nlohmann_json was not created.")
endif()

get_target_property(KERNAUTH_SODIUM_INCLUDES sodium INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "kernauth_sdk links libsodium target sodium (${KERNAUTH_SODIUM_INCLUDES}) and libcurl target CURL::libcurl")

add_library(kernauth_sdk STATIC
  src/version.cpp
  src/canonical.cpp
  src/verify.cpp
  src/nonce.cpp
  src/client.cpp
  src/cache.cpp
  src/curl_transport.cpp)
target_include_directories(kernauth_sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(kernauth_sdk PUBLIC sodium nlohmann_json::nlohmann_json CURL::libcurl)
target_compile_features(kernauth_sdk PUBLIC cxx_std_20)

add_executable(kernauth_example examples/console.cpp)
target_link_libraries(kernauth_example PRIVATE kernauth_sdk)

add_executable(kernauth_integrate examples/integrate.cpp)
target_link_libraries(kernauth_integrate PRIVATE kernauth_sdk)

add_executable(kernauth_sdk_version_check tests/version_check.cpp)
target_link_libraries(kernauth_sdk_version_check PRIVATE kernauth_sdk)

file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../apps/api/src/entitlements/vectors.json" KERNAUTH_VECTORS_JSON)

enable_testing()
add_test(NAME version_check COMMAND kernauth_sdk_version_check)
if(EXISTS "${KERNAUTH_VECTORS_JSON}")
  add_executable(kernauth_sdk_tests tests/sdk_tests.cpp)
  target_link_libraries(kernauth_sdk_tests PRIVATE kernauth_sdk)
  target_compile_definitions(kernauth_sdk_tests PRIVATE "KERNAUTH_VECTORS_JSON=\"${KERNAUTH_VECTORS_JSON}\"")
  add_test(NAME sdk_tests COMMAND kernauth_sdk_tests)
else()
  message(STATUS "kernauth_sdk_tests skipped. The entitlement vectors live in the KernAuth monorepo.")
endif()
