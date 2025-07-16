exp_add_library(exp_frida_plugin_ssl_dumper)

embed_js_file(
        TARGET exp_frida_plugin_ssl_dumper
        JS_FILE ${CMAKE_CURRENT_SOURCE_DIR}/SslDumper.js
)

target_sources(exp_frida_plugin_ssl_dumper PRIVATE
        SslDumper.h
        SslDumper.cpp
)