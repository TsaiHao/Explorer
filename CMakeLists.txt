cmake_minimum_required(VERSION 3.20)
project(explorer LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(TARGET_ANDROID ON CACHE BOOL "Compile for Android platform")
set(ENABLE_DEBUG OFF CACHE BOOL "Enable debug logs")

if (TARGET_ANDROID)
    include(${ANDROID_NDK}/build/cmake/android.toolchain.cmake)
endif ()

set(SOURCES
        src/main.cpp
        src/Application.cpp
        src/Application.h
)

set(PLUGIN_SOURCES
        src/plugins/Plugin.h
        src/plugins/Plugin.cpp
        src/plugins/function_tracer/FunctionTracer.h
        src/plugins/function_tracer/FunctionTracer.cpp
)

set(FRIDA_WRAPPER_SOURCES
        src/frida/Device.cpp
        src/frida/Device.h
        src/frida/Script.cpp
        src/frida/Script.h
        src/frida/Session.cpp
        src/frida/Session.h
)

set(UTILS_SOURCES
        src/utils/Log.cpp
        src/utils/Log.h
        src/utils/System.cpp
        src/utils/System.h
        src/utils/Status.cpp
        src/utils/Status.h
        src/utils/SmallMap.h
        src/utils/Macros.h
)

add_executable(${PROJECT_NAME} ${SOURCES} ${FRIDA_WRAPPER_SOURCES} ${UTILS_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE src)

if (ENABLE_DEBUG)
    target_compile_definitions(${PROJECT_NAME} PRIVATE EXP_DEBUG)
endif ()

if (TARGET_ANDROID)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TARGET_ANDROID)
    target_link_libraries(${PROJECT_NAME} PRIVATE log)
else ()
    target_link_libraries(${PROJECT_NAME} PRIVATE
            resolv
            "-framework CoreFoundation"
            "-framework IOKit"
            "-framework AppKit"
            "-framework Cocoa"
            "-framework Security")
endif ()

add_subdirectory(third_party)
target_link_libraries(${PROJECT_NAME} PRIVATE DEPS)

add_subdirectory(tools)
