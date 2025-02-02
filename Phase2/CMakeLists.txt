# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.15)
# option() honors normal variables.
# see: https://cmake.org/cmake/help/git-stage/policy/CMP0077.html
if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()
# Honor symbol visibility properties for all target types.
# see: https://cmake.org/cmake/help/git-stage/policy/CMP0063.html
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif()
if(POLICY CMP0066)
    cmake_policy(SET CMP0066 NEW)
endif()
if(POLICY CMP0067)
    cmake_policy(SET CMP0067 NEW)
endif()

project(liboqs C ASM)

option(OQS_DIST_BUILD "Build distributable library with optimized code for several CPU microarchitectures. Enables run-time CPU feature detection." ON)
option(OQS_BUILD_ONLY_LIB "Build only liboqs and do not expose build targets for tests, documentation, and pretty-printing available." OFF)
set(OQS_MINIMAL_BUILD "" CACHE STRING "Only build specifically listed algorithms.")
option(OQS_LIBJADE_BUILD "Enable formally verified implementation of supported algorithms from libjade." OFF)
option(OQS_PERMIT_UNSUPPORTED_ARCHITECTURE "Permit compilation on an an unsupported architecture." OFF)
option(OQS_STRICT_WARNINGS "Enable all compiler warnings." OFF)
option(OQS_EMBEDDED_BUILD "Compile liboqs for an Embedded environment without a full standard library." OFF)

# Libfuzzer isn't supported on gcc
if('${CMAKE_C_COMPILER_ID}' STREQUAL 'Clang')
    option(OQS_BUILD_FUZZ_TESTS "Build fuzz test suite" OFF)
endif()


set(OQS_OPT_TARGET auto CACHE STRING "The target microarchitecture for optimization.")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(OQS_VERSION_MAJOR 0)
set(OQS_VERSION_MINOR 12)
set(OQS_VERSION_PATCH 1)
set(OQS_VERSION_PRE_RELEASE "-dev")
set(OQS_VERSION_TEXT "${OQS_VERSION_MAJOR}.${OQS_VERSION_MINOR}.${OQS_VERSION_PATCH}${OQS_VERSION_PRE_RELEASE}")
set(OQS_COMPILE_BUILD_TARGET "${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_HOST_SYSTEM}")
set(OQS_MINIMAL_GCC_VERSION "7.1.0")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Determine the flags for fuzzing. Use OSS-Fuzz's configuration if available, otherwise fall back to defaults.
if(DEFINED ENV{LIB_FUZZING_ENGINE})
    set(FUZZING_ENGINE $ENV{LIB_FUZZING_ENGINE})
    set(FUZZING_COMPILE_FLAGS "")
    set(FUZZING_LINK_FLAGS "${FUZZING_ENGINE}")
else()
    set(FUZZING_COMPILE_FLAGS "-fsanitize=fuzzer,address")
    set(FUZZING_LINK_FLAGS "-fsanitize=fuzzer,address")
endif()

# heuristic check to see whether we're running on a RaspberryPi
if(EXISTS "/opt/vc/include/bcm_host.h")
	add_definitions( -DOQS_USE_RASPBERRY_PI )
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(ARCH "x86_64")
    set(ARCH_X86_64 ON)
    if(${OQS_DIST_BUILD})
        set(OQS_DIST_X86_64_BUILD ON)
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(OQS_DEBUG_BUILD ON)
else()
    set(OQS_DEBUG_BUILD OFF)
endif()

option(OQS_SPEED_USE_ARM_PMU "Use ARM Performance Monitor Unit during benchmarking" OFF)

if(WIN32 AND NOT (MINGW OR MSYS OR CYGWIN))
    set(CMAKE_GENERATOR_CC cl)
endif()

include(.CMake/compiler_opts.cmake)
include(.CMake/alg_support.cmake)


set(PUBLIC_HEADERS ${PROJECT_SOURCE_DIR}/src/oqs.h
                   ${PROJECT_SOURCE_DIR}/src/common/aes/aes_ops.h
                   ${PROJECT_SOURCE_DIR}/src/common/common.h
                   ${PROJECT_SOURCE_DIR}/src/common/rand/rand.h
                   ${PROJECT_SOURCE_DIR}/src/common/sha2/sha2_ops.h
                   ${PROJECT_SOURCE_DIR}/src/common/sha3/sha3_ops.h
                   ${PROJECT_SOURCE_DIR}/src/common/sha3/sha3x4_ops.h
                   ${PROJECT_SOURCE_DIR}/src/kem/kem.h
                   ${PROJECT_SOURCE_DIR}/src/sig/sig.h
                   ${PROJECT_SOURCE_DIR}/src/sig_stfl/sig_stfl.h)

set(INTERNAL_HEADERS ${PROJECT_SOURCE_DIR}/src/common/aes/aes.h
                     ${PROJECT_SOURCE_DIR}/src/common/rand/rand_nist.h
                     ${PROJECT_SOURCE_DIR}/src/common/sha2/sha2.h
                     ${PROJECT_SOURCE_DIR}/src/common/sha3/sha3.h
                     ${PROJECT_SOURCE_DIR}/src/common/sha3/sha3x4.h)


if(OQS_ENABLE_KEM_KYBER)
    set(PUBLIC_HEADERS ${PUBLIC_HEADERS} ${PROJECT_SOURCE_DIR}/src/kem/kyber/kem_kyber.h)
endif()

if(OQS_ENABLE_SIG_DILITHIUM)
    set(PUBLIC_HEADERS ${PUBLIC_HEADERS} ${PROJECT_SOURCE_DIR}/src/sig/dilithium/sig_dilithium.h)
endif()

##### OQS_COPY_FROM_UPSTREAM_FRAGMENT_INCLUDE_HEADERS_END
if(OQS_ENABLE_SIG_STFL_XMSS)
    set(PUBLIC_HEADERS ${PUBLIC_HEADERS} ${PROJECT_SOURCE_DIR}/src/sig_stfl/xmss/sig_stfl_xmss.h)
endif()
if(OQS_ENABLE_SIG_STFL_LMS)
    set(PUBLIC_HEADERS ${PUBLIC_HEADERS} ${PROJECT_SOURCE_DIR}/src/sig_stfl/lms/sig_stfl_lms.h)
endif()
execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/include/oqs)
execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${PUBLIC_HEADERS} ${PROJECT_BINARY_DIR}/include/oqs)
execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${INTERNAL_HEADERS} ${PROJECT_BINARY_DIR}/include/oqs)
configure_file(src/oqsconfig.h.cmake ${PROJECT_BINARY_DIR}/include/oqs/oqsconfig.h)
set(PUBLIC_HEADERS ${PUBLIC_HEADERS} ${PROJECT_BINARY_DIR}/include/oqs/oqsconfig.h)

include_directories(${PROJECT_BINARY_DIR}/include)
add_subdirectory(src)
# -------------------------- open ssl ---------------------


message("------------------ OPENSSL --------------------")

message(${PROJECT_SOURCE_DIR})
 set(OPENSSL_ROOT_DIR "${PROJECT_SOURCE_DIR}/OpenSSL-Win64/lib/VC/x64/MT")
 set(OPENSSL_USE_STATIC_LIBS TRUE)
 set(OPENSSL_MSVC_STATIC_RT TRUE)

 
 set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.lib")
 set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/llibssl.lib")
    

 # Add these before find_package
set(CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")

set(OPENSSL_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/OpenSSL-Win64/include")

# Find OpenSSL package
find_package(OpenSSL 3.4.0 REQUIRED)

if(OPENSSL_FOUND)
    add_definitions(-DHAVE_OPENSSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# Print OpenSSL details for debugging
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")


# -------------------------- open ssl done ---------------------

if(NOT ${OQS_BUILD_ONLY_LIB})
    add_subdirectory(tests)
endif()

