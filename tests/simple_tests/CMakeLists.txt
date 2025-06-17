add_executable(sp_tests
    SubprocessTests.cpp
)

target_link_libraries(sp_tests PRIVATE ${PROJECT_NAME}_utils COMMON_SETTINGS)