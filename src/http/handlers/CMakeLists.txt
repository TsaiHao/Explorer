# Session command handlers
target_sources(exp_http PRIVATE 
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

target_include_directories(exp_http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})