add_library(DEPS INTERFACE)

target_link_libraries(DEPS INTERFACE frida/lib/libfrida-core.a)
target_include_directories(DEPS INTERFACE frida/include)