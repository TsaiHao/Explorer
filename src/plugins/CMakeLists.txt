add_subdirectory(function_tracer)

exp_add_library(exp_frida_plugins)

target_sources(exp_frida_plugins
    PRIVATE
    Plugin.h
    Plugin.cpp
)

target_link_libraries(exp_frida_plugins
    PRIVATE
    exp_frida_plugin_function_tracer
)