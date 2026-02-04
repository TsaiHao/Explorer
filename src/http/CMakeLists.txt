# Add subdirectories
add_subdirectory(handlers)

# HTTP API Infrastructure
add_library(exp_http STATIC
    RequestHandler.cpp
    AsyncRequestHandler.cpp
    EnhancedRequestHandler.cpp
    ApiRouter.cpp
    ApiSchema.cpp
    HttpServer.cpp
)

target_link_libraries(exp_http
    COMMON_SETTINGS
    DEPS
    exp_http_handlers
)

target_include_directories(exp_http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})