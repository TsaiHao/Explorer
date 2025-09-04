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

add_subdirectory(sqlite)

target_include_directories(DEPS INTERFACE ${CMAKE_CURRENT_LIST_DIR})