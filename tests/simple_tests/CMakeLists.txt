add_executable(sp_tests
    SubprocessTests.cpp
)

target_link_libraries(sp_tests PRIVATE 
    exp_utils 
)