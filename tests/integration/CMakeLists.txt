# Integration tests for Explorer daemon
cmake_minimum_required(VERSION 3.20)

# Integration test executable
add_executable(daemon_integration_test
    DaemonIntegrationTest.cpp
    integration_test_main.cpp
)

# Link against all required libraries
target_link_libraries(daemon_integration_test
    COMMON_SETTINGS
    DEPS
    exp_application_daemon
    exp_http_server
    exp_http_handlers
    exp_utils_error_handling
    exp_utils_state_manager
    exp_frida_device
    exp_frida_session
    Threads::Threads
)

# Include directories
target_include_directories(daemon_integration_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Set test properties
set_target_properties(daemon_integration_test PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Test runner script
add_custom_target(run_integration_tests
    COMMAND daemon_integration_test
    DEPENDS daemon_integration_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running daemon integration tests"
)

# Optional: Add to CTest if available
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.10")
    include(CTest)
    if(BUILD_TESTING)
        add_test(
            NAME DaemonIntegrationTests
            COMMAND daemon_integration_test
        )
        set_tests_properties(DaemonIntegrationTests PROPERTIES
            TIMEOUT 300
            LABELS "integration"
        )
    endif()
endif()