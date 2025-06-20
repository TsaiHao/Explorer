exp_add_library(exp_frida_plugin_function_tracer)

embed_js_file(
        TARGET exp_frida_plugin_function_tracer
        JS_FILE ${CMAKE_CURRENT_SOURCE_DIR}/FunctionTracer.js
)

target_sources(exp_frida_plugin_function_tracer PRIVATE
        FunctionTracer.h
        FunctionTracer.cpp
)