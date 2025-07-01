add_executable(sp_tests
    SubprocessTests.cpp
)

target_link_libraries(sp_tests PRIVATE 
    exp_utils 
)

add_executable(db_tests
    DBTests.cpp
)

target_link_libraries(db_tests PRIVATE 
    exp_utils 
)