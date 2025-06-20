add_subdirectory(frida)
add_subdirectory(plugins)
add_subdirectory(utils)

add_executable(${PROJECT_NAME} 
    main.cpp
    Application.h
    Application.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    COMMON_SETTINGS
    DEPS
    exp_frida_plugins
    exp_frida
    exp_utils
)