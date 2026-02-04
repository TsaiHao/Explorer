# Session command handlers
add_library(exp_http_handlers STATIC
    StartSessionHandler.cpp
    StopSessionHandler.cpp
    StatusHandler.cpp
    ListSessionsHandler.cpp
    SessionDispatcherHandler.cpp
    StatsHandler.cpp
    HealthHandler.cpp
    MetricsHandler.cpp
    DrainMessagesHandler.cpp
)

target_link_libraries(exp_http_handlers
    COMMON_SETTINGS
    DEPS
)

target_include_directories(exp_http_handlers PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})