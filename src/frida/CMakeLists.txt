exp_add_library(exp_frida)

embed_js_file(
    TARGET exp_frida
    JS_FILE ${CMAKE_CURRENT_SOURCE_DIR}/java_runtime.js
)

target_sources(exp_frida PRIVATE
    Device.h
    Device.cpp
    Script.h
    Script.cpp
    Session.h
    Session.cpp
)