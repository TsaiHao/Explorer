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

# Strip the Vega binary after build. CMAKE_STRIP resolves to the host strip,
# which can't process an armhf ELF, so use the toolchain's arm strip.
if (TARGET_VEGA)
    find_program(ARM_STRIP arm-linux-gnueabihf-strip)
    if (ARM_STRIP)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${ARM_STRIP} $<TARGET_FILE:${PROJECT_NAME}>
            COMMENT "Stripping ${PROJECT_NAME} with ${ARM_STRIP}"
        )
    else ()
        message(WARNING "arm-linux-gnueabihf-strip not found; Vega binary will not be stripped")
    endif ()
endif ()