add_subdirectory(frida)
add_subdirectory(http)
add_subdirectory(plugins)
add_subdirectory(utils)

add_executable(${PROJECT_NAME}
    main.cpp
    Application.h
    Application.cpp
    ApplicationDaemon.h
    ApplicationDaemon.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    COMMON_SETTINGS
    DEPS
    exp_frida_plugins
    exp_frida
    exp_http
    exp_utils
)