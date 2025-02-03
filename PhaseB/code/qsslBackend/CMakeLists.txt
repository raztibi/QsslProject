# SPDX-License-Identifier: MIT
project(QSSL)
option(OQS_ENABLE_TEST_CONSTANT_TIME "Build test suite with support for Valgrind-based detection of non-constant time behaviour." OFF)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
   CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wbad-function-cast)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wcast-qual)
    add_compile_options(-Wnarrowing)
    add_compile_options(-Wconversion)
endif()
if (MINGW OR MSYS OR CYGWIN)
    add_definitions(-D__USE_MINGW_ANSI_STDIO=1)
    add_compile_options(-Wno-unknown-pragmas)
    add_compile_options(-Wno-unused-parameter)
endif()
if(WIN32 AND NOT (MINGW OR MSYS OR CYGWIN))
    # ignore warning for test apps
    add_compile_options(/wd4996 /wd4244)
endif()

if(OQS_USE_OPENSSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

if(NOT WIN32)
    set(LIBM m)
endif()

# List oqs-internal after oqs so that oqs has linking precedence.
if(${OQS_USE_OPENSSL})
    find_package(OpenSSL 1.1.1 REQUIRED)
    set(TEST_DEPS oqs oqs-internal ${LIBM} OpenSSL::Crypto)
else()
    set(TEST_DEPS oqs oqs-internal ${LIBM})
endif()

if(OQS_USE_PTHREADS)
    set(TEST_DEPS ${TEST_DEPS} Threads::Threads)
endif()

set(PYTHON3_EXEC python)

# SIG API tests
add_executable(example_sig example_sig.c)
target_link_libraries(example_sig PRIVATE ${TEST_DEPS})

add_executable(example_kem example_kem.c)
target_link_libraries(example_kem PRIVATE ${TEST_DEPS})

# KEM API tests
add_executable(server server.c crypto_functions.c socket_functions.c)
target_include_directories(server PRIVATE .)
target_link_libraries(server PRIVATE ${TEST_DEPS})

add_executable(client client.c crypto_functions.c socket_functions.c)
target_include_directories(client PRIVATE .)
target_link_libraries(client PRIVATE ${TEST_DEPS})

if(OPENSSL_FOUND)
# Link libraries
target_link_libraries(server PRIVATE
    ${OPENSSL_LIBRARIES}
    # For Windows, you might also need these
    crypt32
    ws2_32
)
target_link_libraries(client PRIVATE
    ${OPENSSL_LIBRARIES}
    # For Windows, you might also need these
    crypt32
    ws2_32
)
endif()


if (CMAKE_GENERATOR MATCHES "Visual Studio")
    # With Visual studio the output of tests go into a folder with the configuration option. Force it to the same folder as if
    # generating with Ninja
    set_target_properties(
        dump_alg_info ${KEM_TESTS} ${SIG_TESTS}
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${CMAKE_BINARY_DIR}/tests"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_BINARY_DIR}/tests"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/tests"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL     "${CMAKE_BINARY_DIR}/tests")
endif()

