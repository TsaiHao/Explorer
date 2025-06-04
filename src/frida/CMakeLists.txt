target_sources(${PROJECT_NAME} PRIVATE
    Device.h
    Device.cpp
    Script.h
    Script.cpp
    Session.h
    Session.cpp
)

embed_js_file(
    TARGET_SOURCE Script.cpp
    JS_FILE ${CMAKE_CURRENT_SOURCE_DIR}/java_runtime.js
)