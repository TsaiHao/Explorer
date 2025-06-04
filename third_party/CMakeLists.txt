add_library(DEPS INTERFACE)

if(DEFINED FRIDA_LOCAL_PATH AND EXISTS "${FRIDA_LOCAL_PATH}")
    message(STATUS "Using custom Frida libraries from pkgconfig path: ${FRIDA_LOCAL_PATH}")

    set(ENV{frida_sdk_prefix} "/Users/zaijun/projects/frida/deps/sdk-android-arm")
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
    target_link_directories(DEPS INTERFACE ${FRIDA_LOCAL_PATH}/deps/sdk-android-arm/lib)
    target_include_directories(DEPS INTERFACE 
        ${FRIDA_LOCAL_PATH}/deps/sdk-android-arm/include
        ${FRIDA_LOCAL_PATH}/deps/sdk-android-arm/include/glib-2.0
        ${FRIDA_LOCAL_PATH}/deps/sdk-android-arm/lib/glib-2.0/include
        ${FRIDA_LOCAL_PATH}/deps/sdk-android-arm/include/json-glib-1.0
        ${FRIDA_LOCAL_PATH}/android-server/install/include/frida-1.0

        ${CMAKE_CURRENT_SOURCE_DIR}
    )

    foreach(module ${FRIDA_MODULES})
        target_link_libraries(DEPS INTERFACE ${module})
    endforeach()
else()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/frida/lib/libfrida-core.a")
        message(STATUS "Using hardcoded Frida library path")
        target_link_libraries(DEPS INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/frida/lib/libfrida-core.a)
        target_include_directories(DEPS INTERFACE 
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/frida/include
        )
    else()
        message(FATAL_ERROR "Neither FRIDA_PKGCONFIG_PATH is set nor hardcoded Frida library found. "
                "Please set FRIDA_PKGCONFIG_PATH to your custom pkgconfig directory or "
                "ensure the hardcoded library exists at ${CMAKE_CURRENT_SOURCE_DIR}/frida/lib/libfrida-core.a")
    endif()
endif()