include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE
)

# Prevent GoogleTest from overriding compiler/linker options
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

# Minimal static lib for testable utils (no Frida, no Android deps)
add_library(test_utils STATIC
    ${CMAKE_SOURCE_DIR}/src/utils/Status.cpp
)
target_include_directories(test_utils PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
    ${PROJECT_BINARY_DIR}/generated
)
target_link_libraries(test_utils PUBLIC COMMON_SETTINGS)

# --- MessageCacheTest (no mocks, pure logic) ---
add_executable(MessageCacheTest MessageCacheTest.cpp)
target_link_libraries(MessageCacheTest PRIVATE test_utils GTest::gtest_main)
add_test(NAME MessageCacheTest COMMAND MessageCacheTest)

# --- ResultTest (no mocks, pure logic) ---
add_executable(ResultTest ResultTest.cpp)
target_link_libraries(ResultTest PRIVATE test_utils GTest::gtest_main)
add_test(NAME ResultTest COMMAND ResultTest)
