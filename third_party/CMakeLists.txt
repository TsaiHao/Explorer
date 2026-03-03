add_library(DEPS INTERFACE)

if(DEFINED FRIDA_LOCAL_PATH AND EXISTS "${FRIDA_LOCAL_PATH}")
    # todo: implement this branch
    message(STATUS "Using custom Frida libraries from pkgconfig path: ${FRIDA_LOCAL_PATH}")

    #set(ENV{frida_sdk_prefix} "/Users/zaijun/projects/frida/deps/sdk-android-arm")
    find_package(PkgConfig REQUIRED)

    set(ENV{PKG_CONFIG_PATH} "${FRIDA_LOCAL_PATH}/android-server/install/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

    set(FRIDA_MODULES
            frida-base-1.0
            frida-core-1.0
            frida-gum-1.0
            frida-gum-heap-1.0
            frida-gum-prof-1.0
            frida-gumjs-1.0
            frida-gumjs-inspector-1.0
            frida-payload-1.0
    )

    link_frida_library(DEPS "frida-base-1.0")
    link_frida_library(DEPS "frida-core-1.0")
    link_frida_library(DEPS "frida-gum-1.0")

    target_compile_definitions(DEPS INTERFACE USING_LOCAL_FRIDA)
else()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/frida/lib/libfrida-core.a")
        message(STATUS "Using hardcoded Frida library path")
        target_link_libraries(DEPS INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/frida/lib/libfrida-core.a)
        target_include_directories(DEPS INTERFACE 
            ${CMAKE_CURRENT_SOURCE_DIR}/frida/include
        )
    else()
        message(FATAL_ERROR "Neither FRIDA_PKGCONFIG_PATH is set nor hardcoded Frida library found. "
                "Please set FRIDA_PKGCONFIG_PATH to your custom pkgconfig directory or "
                "ensure the hardcoded library exists at ${CMAKE_CURRENT_SOURCE_DIR}/frida/lib/libfrida-core.a")
    endif()
endif()

if (ENABLE_SQLITE)
    add_subdirectory(sqlite)
    target_compile_definitions(DEPS INTERFACE ENABLE_SQLITE)
endif ()

set(BUILD_SHARED_LIBS FALSE)

# Only need Foundation, Net, and Util for HTTP server
# Disable all unused modules
set(ENABLE_XML FALSE)
set(ENABLE_JSON FALSE)
set(ENABLE_ENCODINGS FALSE)
set(ENABLE_MONGODB FALSE)
set(ENABLE_REDIS FALSE)
set(ENABLE_PROMETHEUS FALSE)
set(ENABLE_ZIP FALSE)
set(ENABLE_DATA FALSE)
set(ENABLE_DATA_SQLITE FALSE)
set(ENABLE_DATA_MYSQL FALSE)
set(ENABLE_DATA_POSTGRESQL FALSE)
set(ENABLE_DATA_ODBC FALSE)
set(ENABLE_ACTIVERECORD FALSE)
set(ENABLE_ACTIVERECORD_COMPILER FALSE)
set(ENABLE_PAGECOMPILER FALSE)
set(ENABLE_PAGECOMPILER_FILE2PAGE FALSE)
set(ENABLE_NETSSL FALSE)
set(ENABLE_CRYPTO FALSE)
set(ENABLE_JWT FALSE)
add_subdirectory(poco)
target_link_libraries(DEPS INTERFACE Poco::Net)

target_include_directories(DEPS INTERFACE ${CMAKE_CURRENT_LIST_DIR})