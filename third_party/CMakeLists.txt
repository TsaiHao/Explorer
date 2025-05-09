add_library(DEPS INTERFACE)

target_link_libraries(DEPS INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/frida/lib/libfrida-core.a)
target_include_directories(DEPS INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)