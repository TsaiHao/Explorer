cmake_minimum_required(VERSION 3.20)
project(explorer LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(ANDROID_NDK "" CACHE PATH "Path to Android NDK")
# set(ANDROID_SDK "" CACHE PATH "Path to Android SDK")

if (NOT EXISTS ${ANDROID_NDK})
    message(FATAL_ERROR "Please specify ANDROID_NDK path: -DANDROID_NDK=<path>")
endif ()

set(ANDROID_PLATFORM android-21)  # Minimum API level
set(ANDROID_ABI armeabi-v7a)     # Target architecture
set(ANDROID_STL c++_shared)      # C++ STL to use

include(${ANDROID_NDK}/build/cmake/android.toolchain.cmake)

set(SOURCES
        src/main.cpp
        src/Argument.h
        src/Argument.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

#target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_11)

add_subdirectory(third_party)
target_link_libraries(${PROJECT_NAME} DEPS)

add_subdirectory(tools)