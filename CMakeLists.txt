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

set(LOCAL_CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(${LOCAL_CMAKE_MODULE_PATH}/EmbedJs.cmake)

set(SOURCES
        src/main.cpp
        src/Application.cpp
        src/Application.h
)
add_executable(${PROJECT_NAME} ${SOURCES})

add_subdirectory(src)

target_sources(${PROJECT_NAME} PRIVATE ${FRIDA_WRAPPER_SOURCES} ${UTILS_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE src)

if (ENABLE_DEBUG)
    target_compile_definitions(${PROJECT_NAME} PRIVATE EXP_DEBUG)
endif ()

if (TARGET_ANDROID)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TARGET_ANDROID)
    target_link_libraries(${PROJECT_NAME} PRIVATE log)
endif ()

add_subdirectory(third_party)
target_link_libraries(${PROJECT_NAME} PRIVATE DEPS)

add_subdirectory(tools)
