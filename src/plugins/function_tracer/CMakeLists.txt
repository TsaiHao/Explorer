target_sources(${PROJECT_NAME} PRIVATE
        FunctionTracer.h
        FunctionTracer.cpp
)

embed_js_file(
        TARGET_SOURCE FunctionTracer.cpp
        JS_FILE ${CMAKE_CURRENT_SOURCE_DIR}/FunctionTracer.js
)