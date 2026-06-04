cmake_minimum_required(VERSION 3.20)
project(explorer LANGUAGES CXX C)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)

# Get git commit hash
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE VERSION_PATCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    set(VERSION_PATCH "unknown")
endif()

configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/version.h.in"
    "${PROJECT_BINARY_DIR}/generated/version.h"
    @ONLY
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(TARGET_ANDROID ON CACHE BOOL "Compile for Android platform")
set(TARGET_VEGA OFF CACHE BOOL "Compile for Vega platform")
set(ENABLE_DEBUG OFF CACHE BOOL "Enable debug logs")

set(STATIC_LIBSTDCPP OFF CACHE BOOL "Link libstdc++ statically")

option(ENABLE_SQLITE "Enable features that require sqlite(data output). Enabling it would build sqlite3" OFF)
option(ENABLE_COROUTINES "Enable C++20 coroutine-based async Frida APIs" ON)

if (TARGET_ANDROID)
    include(${ANDROID_NDK}/build/cmake/android.toolchain.cmake)
endif ()

set(LOCAL_CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(${LOCAL_CMAKE_MODULE_PATH}/Dependencies.cmake)
include(${LOCAL_CMAKE_MODULE_PATH}/EmbedJs.cmake)
include(${LOCAL_CMAKE_MODULE_PATH}/LocalFridaFinder.cmake)

if (STATIC_LIBSTDCPP)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
endif ()

# Fetch third-party dependencies at configure time
install_dependencies()

add_library(COMMON_SETTINGS INTERFACE)
target_include_directories(COMMON_SETTINGS INTERFACE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_BINARY_DIR}/generated
)
target_compile_options(COMMON_SETTINGS INTERFACE -Wall -Wextra -Werror -g)

# Add threading support for cpp-httplib
find_package(Threads REQUIRED)
target_link_libraries(COMMON_SETTINGS INTERFACE Threads::Threads)

if (ENABLE_DEBUG)
    target_compile_definitions(COMMON_SETTINGS INTERFACE EXP_DEBUG)
    target_compile_definitions(COMMON_SETTINGS INTERFACE SPDLOG_ACTIVE_LEVEL=1) # debug
else ()
    target_compile_definitions(COMMON_SETTINGS INTERFACE SPDLOG_ACTIVE_LEVEL=2) # info
    # Enable -Oz optimization for release builds on Android
    if (TARGET_ANDROID)
        target_compile_options(COMMON_SETTINGS INTERFACE -Oz)
    endif ()
endif ()

if (TARGET_ANDROID)
    target_compile_definitions(COMMON_SETTINGS INTERFACE TARGET_ANDROID)
    target_compile_options(COMMON_SETTINGS INTERFACE -Wall -Wextra -Werror)
    target_compile_options(COMMON_SETTINGS INTERFACE
        $<$<COMPILE_LANG_AND_ID:CXX,Clang>:-Wno-unused-command-line-argument>
    )
    target_link_libraries(COMMON_SETTINGS INTERFACE log)
elseif (TARGET_VEGA)
    target_compile_definitions(COMMON_SETTINGS INTERFACE TARGET_VEGA)
    # Silence GCC's -Wpsabi notes on 32-bit ARM (calling-convention change in
    # GCC 7.1). Purely informational with a single GCC 15.2 toolchain.
    target_compile_options(COMMON_SETTINGS INTERFACE -Wno-psabi)
    # Frida's prebuilt libfrida-core.a bundles BoringSSL asm (e.g.
    # ghash-armv4.S) whose objects lack a .note.GNU-stack section, which
    # otherwise marks the whole binary's stack executable. Force a
    # non-executable stack at link time.
    target_link_options(COMMON_SETTINGS INTERFACE -Wl,-z,noexecstack)
endif ()

# ---------------------------------------------------------------------------
# C++20 coroutine detection
# ---------------------------------------------------------------------------
if(ENABLE_COROUTINES)
    include(CheckIncludeFileCXX)
    include(CheckCXXSourceCompiles)

    check_include_file_cxx("coroutine" HAS_COROUTINE_HEADER)

    if(HAS_COROUTINE_HEADER)
        check_cxx_source_compiles("
            #include <coroutine>
            struct Awaitable {
                bool await_ready() { return false; }
                void await_suspend(std::coroutine_handle<>) {}
                void await_resume() {}
            };
            int main() { return 0; }
        " HAS_COROUTINE_SUPPORT)
    endif()

    if(HAS_COROUTINE_SUPPORT)
        message(STATUS "C++20 coroutines: ENABLED")
        target_compile_definitions(COMMON_SETTINGS INTERFACE EXPLORER_USE_COROUTINES)
        # GCC requires -fcoroutines flag
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(COMMON_SETTINGS INTERFACE -fcoroutines)
        endif()
    else()
        message(WARNING "C++20 coroutines requested but not supported by compiler — falling back to sync APIs")
    endif()
else()
    message(STATUS "C++20 coroutines: DISABLED (using sync Frida APIs)")
endif()

add_subdirectory(third_party)
add_subdirectory(src)

add_subdirectory(tools)
if(NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    add_subdirectory(tests)
endif()