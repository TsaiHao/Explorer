#include "ApplicationDaemon.h"
#include "frida/Device.h"
#include "http/RequestHandler.h"
#include "http/handlers/HealthHandler.h"
#include "http/handlers/ListSessionsHandler.h"
#include "http/handlers/MetricsHandler.h"
#include "http/handlers/SessionDispatcherHandler.h"
#include "http/handlers/StartSessionHandler.h"
#include "http/handlers/StatsHandler.h"
#include "http/handlers/StatusHandler.h"
#include "http/handlers/DrainMessagesHandler.h"
#include "http/handlers/StopSessionHandler.h"
#include "utils/Log.h"
#include "utils/Status.h"
#include "utils/System.h"
#include "version.h"

#include "spdlog/sinks/android_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <signal.h>
#include <thread>

namespace {

void AndroidEnvCheck() {
#ifdef TARGET_ANDROID
  // Check if the application is running as root
  if (getuid() != 0) {
    LOGE("This application must be run as root, exiting");
    exit(EXIT_FAILURE);
  }
  // Turn SELinux to permissive mode
  frida_selinux_patch_policy();
#endif
}

void InitLogger() {
  std::vector<spdlog::sink_ptr> sinks;

  auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  sinks.push_back(stdout_sink);

  auto android_sink =
      std::make_shared<spdlog::sinks::android_sink_mt>("ExplorerDaemon", true);
  sinks.push_back(android_sink);

  std::string format_pattern = "[%Y-%m-%d %H:%M:%S.%e] [%P:%t] [%l] %v";

  for (auto &sink : sinks) {
    sink->set_pattern(format_pattern);
  }

  auto logger =
      std::make_shared<spdlog::logger>("default", sinks.begin(), sinks.end());

#ifdef EXP_DEBUG
  logger->set_level(spdlog::level::trace);
#else
  logger->set_level(spdlog::level::info);
#endif

  logger->flush_on(spdlog::level::info);

  spdlog::set_default_logger(logger);
  spdlog::flush_every(std::chrono::seconds(1));
}

// Session handlers are now implemented as separate classes
// See http/handlers/ directory for individual handler implementations

} // anonymous namespace

class ApplicationDaemon::Impl {
public:
  explicit Impl(ApplicationDaemon& parent, const std::vector<std::string_view> &args);
  ~Impl();

  Status Initialize();
  Status Run();
  void Shutdown();
  bool IsRunning() const;

  // Session management methods
  Result<json, Status> StartSession(const json &config);
  Result<json, Status>
  StartSessionWithCancellation(const json &config,
                               std::function<bool()> should_cancel);
  Status StopSession(const std::string &session_id);
  Result<json, Status> GetSessionStatus(const std::string &session_id);
  Result<json, Status> ListSessions(const json &filter);

  Result<json, Status> DrainSessionMessages(const std::string &session_id);

  // State persistence methods
  Result<json, Status> GetDaemonStats();
  Result<json, Status> GetSessionHistory(size_t limit);
  Result<size_t, Status> RecoverState();

private:
  void HandleArgs(const std::vector<std::string_view> &args);
  void SetupSignalHandlers();
  void SetupHttpServer();

  struct LoopDeleter {
    void operator()(GMainLoop *loop) const noexcept { g_main_loop_unref(loop); }
  };

  ApplicationDaemon& m_parent;  // Reference to parent ApplicationDaemon

  std::unique_ptr<GMainLoop, LoopDeleter> m_loop;
  std::unique_ptr<frida::Device> m_device;
  std::unique_ptr<http::HttpServer> m_http_server;
  std::unique_ptr<utils::StateManager> m_state_manager;

  std::atomic<bool> m_running;
  std::atomic<bool> m_shutdown_requested;

  // Daemon configuration
  std::string m_host;
  int m_port;
  bool m_daemon_mode;

  // Statistics
  std::chrono::steady_clock::time_point m_start_time;
};

ApplicationDaemon::Impl::Impl(ApplicationDaemon& parent, const std::vector<std::string_view> &args)
    : m_parent(parent), m_running(false), m_shutdown_requested(false), m_host("0.0.0.0"),
      m_port(34512), m_daemon_mode(true) {

  HandleArgs(args);
}

ApplicationDaemon::Impl::~Impl() {
  if (m_running) {
    Shutdown();
  }
}

Status ApplicationDaemon::Impl::Initialize() {
  LOGI("Initializing Explorer Daemon...");

  InitLogger();
  frida_init();
  AndroidEnvCheck();

  // Record start time
  m_start_time = std::chrono::steady_clock::now();

  // Initialize GMainLoop
  m_loop =
      std::unique_ptr<GMainLoop, LoopDeleter>(g_main_loop_new(nullptr, TRUE));
  if (!m_loop) {
    return SdkFailure("Failed to create GMainLoop");
  }

  // Initialize FRIDA device
  m_device = std::make_unique<frida::Device>();
  if (!m_device) {
    return SdkFailure("Failed to create FRIDA device");
  }

  // Initialize state manager
  m_state_manager = std::make_unique<utils::StateManager>();
  auto state_init = m_state_manager->Initialize();
  if (!state_init.Ok()) {
    LOGE("Failed to initialize state manager: {}", state_init.Message());
    return state_init;
  } else {
    LOGI("State manager initialized successfully, this={}", (void*)this);
  }

  // Perform state recovery
  auto recovery_result =
      m_state_manager->PerformRecovery([](pid_t orphaned_pid) -> bool {
        // Cleanup orphaned FRIDA sessions
        LOGW("Cleaning up orphaned session for PID {}", orphaned_pid);
        // In a real implementation, we would call FRIDA cleanup here
        // For now, just return true to indicate cleanup attempt
        return true;
      });

  if (recovery_result.IsErr()) {
    LOGW("State recovery failed: {}", recovery_result.UnwrapErr().Message());
  } else {
    size_t recovered_sessions = recovery_result.Unwrap();
    LOGI("State recovery completed: {} sessions recovered", recovered_sessions);
  }

  // Setup HTTP server
  SetupHttpServer();

  // Setup signal handlers for daemon operation
  SetupSignalHandlers();

  LOGI("Explorer Daemon initialized successfully");
  return Ok();
}

Status ApplicationDaemon::Impl::Run() {
  LOGI("Starting Explorer Daemon on {}:{}", m_host, m_port);

  // Start HTTP server
  auto server_status = m_http_server->Start();
  if (!server_status.Ok()) {
    return server_status;
  }

  m_running = true;
  LOGI("Explorer Daemon is running - HTTP API available at {}",
       m_http_server->GetServerUrl());

  // Enter main event loop
  while (!m_shutdown_requested && m_loop) {
    //g_main_context_iteration(g_main_loop_get_context(m_loop.get()), TRUE);
      if (g_main_loop_is_running(m_loop.get()) != 0) {
        g_main_loop_run(m_loop.get());
      } else {
        break;
      }
  }

  LOGI("Explorer Daemon main loop exiting...");
  m_running = false;

  return Ok();
}

void ApplicationDaemon::Impl::Shutdown() {
  LOGI("Shutting down Explorer Daemon...");
  m_shutdown_requested = true;

  // Shutdown state manager first to save current state
  if (m_state_manager) {
    auto shutdown_status = m_state_manager->Shutdown();
    if (!shutdown_status.Ok()) {
      LOGE("Failed to shutdown state manager: {}", shutdown_status.Message());
    } else {
      LOGI("State manager shutdown successfully");
    }
  }

  if (m_http_server && m_http_server->IsRunning()) {
    m_http_server->Stop();
  }

  if (m_loop && g_main_loop_is_running(m_loop.get())) {
    g_main_loop_quit(m_loop.get());
  }

  m_running = false;
  LOGI("Explorer Daemon shutdown complete");
}

bool ApplicationDaemon::Impl::IsRunning() const { return m_running; }

Result<json, Status> ApplicationDaemon::Impl::StartSession(const json &config) {
  LOGI("Starting new session with config: {}", config.dump());

  // Use the enhanced Device API for session creation
  auto session_result = m_device->CreateSession(config);

  if (session_result.IsOk() && m_state_manager) {
    // Save session state to persistence
    LOGD("Updating state manager with new session");
    json session_data = session_result.Unwrap();
    pid_t session_pid = session_data.value("pid", 0);
    std::string app_name = session_data.value("app", "unknown");

    utils::StateManager::SessionState state(session_pid, app_name, config);
    state.runtime_info = {{"started_at", session_data.value("created_at", 0)},
                          {"status", "active"}};

    auto save_status = m_state_manager->SaveSessionState(state);
    if (!save_status.Ok()) {
      LOGW("Failed to save session state: {}", save_status.Message());
    }
  }

  return session_result;
}

Result<json, Status> ApplicationDaemon::Impl::StartSessionWithCancellation(
    const json &config, std::function<bool()> should_cancel) {
  LOGI("Starting new cancellable session with config: {}", config.dump());

  // Use the enhanced Device API for cancellable session creation
  return m_device->CreateSessionWithCancellation(config, should_cancel);
}

Status ApplicationDaemon::Impl::StopSession(const std::string &session_id) {
  LOGI("Stopping session: {}", session_id);

  try {
    pid_t pid = std::stoi(session_id);

    // Stop the session via Device
    auto device_status = m_device->RemoveSession(pid);

    // Update state manager
    if (m_state_manager) {
      auto state_status = m_state_manager->RemoveSessionState(pid);
      if (!state_status.Ok()) {
        LOGW("Failed to remove session state: {}", state_status.Message());
      }
    }

    return device_status;
  } catch (const std::exception &e) {
    LOGE("Invalid session ID format: {}", session_id);
    return BadArgument("Invalid session ID format");
  }
}

Result<json, Status>
ApplicationDaemon::Impl::DrainSessionMessages(const std::string &session_id) {
  LOGI("Draining messages for session: {}", session_id);

  try {
    pid_t pid = std::stoi(session_id);
    return m_device->DrainSessionMessages(pid);
  } catch (const std::exception &e) {
    LOGE("Invalid session ID format: {}", session_id);
    return Err<Status>(BadArgument("Invalid session ID format"));
  }
}

Result<json, Status>
ApplicationDaemon::Impl::GetSessionStatus(const std::string &session_id) {
  if (session_id.empty()) {
    // Return global daemon status
    auto uptime = std::chrono::steady_clock::now() - m_start_time;
    auto uptime_seconds =
        std::chrono::duration_cast<std::chrono::seconds>(uptime).count();

    // Get session statistics from Device
    json device_stats = m_device->GetSessionStatistics();

    json global_status = {{"daemon_status", "running"},
                          {"uptime_seconds", uptime_seconds},
                          {"http_server", m_http_server->GetServerUrl()},
                          {"device_stats", device_stats}};

    return Ok<json>(global_status);
  }

  // Return specific session status
  LOGI("Getting status for session: {}", session_id);

  try {
    pid_t pid = std::stoi(session_id);
    return m_device->GetSessionInfo(pid);
  } catch (const std::exception &e) {
    LOGE("Invalid session ID format: {}", session_id);
    return Err<Status>(BadArgument("Invalid session ID format"));
  }
}

Result<json, Status> ApplicationDaemon::Impl::ListSessions(const json &filter) {
  LOGI("Listing sessions with filter: {}", filter.dump());

  // Use the enhanced Device API for session listing
  return m_device->ListAllSessions(filter);
}

Result<json, Status> ApplicationDaemon::Impl::GetDaemonStats() {
  if (!m_state_manager) {
    LOGE("State manager not initialized, this={}", (void*)this);
    return Err<Status>(InvalidState("State manager not initialized"));
  }

  auto stats = m_state_manager->GetDaemonStats();

  // Combine with Device statistics
  json device_stats = m_device->GetSessionStatistics();

  json combined_stats = {
      {"daemon_start_time", stats.daemon_start_time.time_since_epoch().count()},
      {"total_sessions_created", stats.total_sessions_created},
      {"active_sessions_count", stats.active_sessions_count},
      {"failed_sessions_count", stats.failed_sessions_count},
      {"state_saves_count", stats.state_saves_count},
      {"recovery_attempts", stats.recovery_attempts},
      {"orphaned_sessions_cleaned", stats.orphaned_sessions_cleaned},
      {"device_stats", device_stats}};

  return Ok<json>(combined_stats);
}

Result<json, Status> ApplicationDaemon::Impl::GetSessionHistory(size_t limit) {
  if (!m_state_manager) {
    return Err<Status>(InvalidState("State manager not initialized"));
  }

  auto history = m_state_manager->GetSessionHistory(limit);

  json history_json = json::array();
  for (const auto &session : history) {
    history_json.push_back(session.ToJson());
  }

  json result = {{"session_history", history_json},
                 {"total_count", history.size()}};

  return Ok<json>(result);
}

Result<size_t, Status> ApplicationDaemon::Impl::RecoverState() {
  if (!m_state_manager) {
    return Err<Status>(InvalidState("State manager not initialized"));
  }

  return m_state_manager->PerformRecovery([](pid_t orphaned_pid) -> bool {
    LOGW("Attempting to cleanup orphaned session for PID {}", orphaned_pid);
    // In a production implementation, this would call FRIDA cleanup
    return true;
  });
}

void ApplicationDaemon::Impl::HandleArgs(
    const std::vector<std::string_view> &args) {
  constexpr std::string_view kHelpOption = "--help";
  constexpr std::string_view kVersionOption = "--version";
  constexpr std::string_view kPortOption = "--port";
  constexpr std::string_view kHostOption = "--host";
  constexpr std::string_view kDaemonOption = "--daemon";

  for (int i = 1; i < static_cast<int>(args.size()); ++i) {
    const auto &arg = args[i];

    if (arg == kHelpOption) {
      std::cout
          << "Usage: explorer [options]\n"
             "Options:\n"
             "  --help         Show this help message\n"
             "  --version      Show version information\n"
             "  --daemon       Run in daemon mode (default)\n"
             "  --host HOST    Bind to specific host (default: 0.0.0.0)\n"
             "  --port PORT    Listen on specific port (default: 34512)\n";
      exit(0);
    } else if (arg == kVersionOption) {
      std::cout << "Explorer Daemon version " << VERSION_STRING << "\n";
      exit(0);
    } else if (arg == kDaemonOption) {
      m_daemon_mode = true;
    } else if (arg == kPortOption && i + 1 < static_cast<int>(args.size())) {
      try {
        m_port = std::stoi(std::string(args[++i]));
        if (m_port <= 0 || m_port > 65535) {
          std::cerr << "Invalid port number: " << m_port << "\n";
          exit(1);
        }
      } catch (const std::exception &e) {
        std::cerr << "Invalid port argument: " << args[i] << "\n";
        exit(1);
      }
    } else if (arg == kHostOption && i + 1 < static_cast<int>(args.size())) {
      m_host = std::string(args[++i]);
    } else {
      std::cerr << "Unknown argument: " << arg << "\n";
      exit(1);
    }
  }
}

void ApplicationDaemon::Impl::SetupSignalHandlers() {
  // Signal handling for daemon mode
  // Note: Signal handlers will be set up in main.cpp for the global instance
  LOGI("Signal handlers will be configured by main application");
}

void ApplicationDaemon::Impl::SetupHttpServer() {
  m_http_server = std::make_unique<http::HttpServer>();
  m_http_server->Configure(m_host, m_port);

  // Configure threading for production-ready concurrency
  // Use optimal thread pool size: 2x CPU cores for I/O bound operations
  size_t thread_pool_size =
      std::max(4u, std::thread::hardware_concurrency() * 2);
  int request_timeout = 60;    // 60 seconds for session operations
  int keep_alive_timeout = 10; // 10 seconds keep alive

  m_http_server->ConfigureThreading(thread_pool_size, request_timeout,
                                    keep_alive_timeout);

  // Use the safely stored parent ApplicationDaemon reference
  ApplicationDaemon *daemon_instance = &m_parent;

  LOGI("SetupHttpServer: Using ApplicationDaemon instance at {}", static_cast<void*>(daemon_instance));

  // Register specialized session command handlers
  auto start_handler =
      std::make_shared<http::StartSessionHandler>(daemon_instance);
  auto stop_handler =
      std::make_shared<http::StopSessionHandler>(daemon_instance);
  auto status_handler = std::make_shared<http::StatusHandler>(daemon_instance);
  auto list_handler =
      std::make_shared<http::ListSessionsHandler>(daemon_instance);
  auto stats_handler = std::make_shared<http::StatsHandler>(daemon_instance);
  auto drain_handler =
      std::make_shared<http::DrainMessagesHandler>(daemon_instance);

  // Register monitoring and health check handlers
  auto health_handler = std::make_shared<http::HealthHandler>(daemon_instance);
  auto metrics_handler =
      std::make_shared<http::MetricsHandler>(daemon_instance);

  // Register handlers with different routes for better API organization
  m_http_server->GetRouter().RegisterPost("/api/v1/session/start",
                                          start_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/stop", stop_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/status",
                                          status_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/list", list_handler);
  m_http_server->GetRouter().RegisterPost("/api/v1/session/messages",
                                          drain_handler);

  // Register state management endpoints
  m_http_server->GetRouter().RegisterGet("/api/v1/daemon/stats", stats_handler);
  m_http_server->GetRouter().RegisterGet("/api/v1/daemon/history",
                                         stats_handler);

  // Register monitoring and diagnostic endpoints
  m_http_server->GetRouter().RegisterGet("/health", health_handler);
  m_http_server->GetRouter().RegisterGet("/api/v1/health", health_handler);
  m_http_server->GetRouter().RegisterGet("/api/v1/metrics", metrics_handler);
  m_http_server->GetRouter().RegisterGet("/api/v1/diagnostics",
                                         metrics_handler);

  // Register the original generic endpoint for backward compatibility
  auto dispatcher_handler =
      std::make_shared<http::SessionDispatcherHandler>(daemon_instance);
  m_http_server->GetRouter().RegisterPost("/api/v1/session",
                                          dispatcher_handler);

  LOGI("HTTP server configured on {}:{}", m_host, m_port);
  LOGI("Registered specialized handlers:");
  LOGI("  POST /api/v1/session/start - Start new sessions");
  LOGI("  POST /api/v1/session/stop - Stop existing sessions");
  LOGI("  POST /api/v1/session/status - Query session/global status");
  LOGI("  POST /api/v1/session/list - List active sessions");
  LOGI("  POST /api/v1/session/messages - Drain cached messages");
  LOGI("  GET  /api/v1/daemon/stats - Get daemon statistics");
  LOGI("  GET  /api/v1/daemon/history - Get session history");
  LOGI("  GET  /health - Health check endpoint");
  LOGI("  GET  /api/v1/health - Detailed health check");
  LOGI("  GET  /api/v1/metrics - Comprehensive metrics");
  LOGI("  GET  /api/v1/diagnostics - System diagnostics");
}

// ApplicationDaemon public interface implementation

ApplicationDaemon::ApplicationDaemon(const std::vector<std::string_view> &args)
    : m_impl(std::make_unique<Impl>(*this, args)) {}

ApplicationDaemon::~ApplicationDaemon() {
  LOGI("Destroying ApplicationDaemon");
}

Status ApplicationDaemon::Initialize() { return m_impl->Initialize(); }

Status ApplicationDaemon::Run() { return m_impl->Run(); }

void ApplicationDaemon::Shutdown() { m_impl->Shutdown(); }

bool ApplicationDaemon::IsRunning() const { return m_impl->IsRunning(); }

Result<json, Status> ApplicationDaemon::StartSession(const json &config) {
  return m_impl->StartSession(config);
}

Result<json, Status> ApplicationDaemon::StartSessionWithCancellation(
    const json &config, std::function<bool()> should_cancel) {
  return m_impl->StartSessionWithCancellation(config, should_cancel);
}

Status ApplicationDaemon::StopSession(const std::string &session_id) {
  return m_impl->StopSession(session_id);
}

Result<json, Status>
ApplicationDaemon::DrainSessionMessages(const std::string &session_id) {
  return m_impl->DrainSessionMessages(session_id);
}

Result<json, Status>
ApplicationDaemon::GetSessionStatus(const std::string &session_id) {
  return m_impl->GetSessionStatus(session_id);
}

Result<json, Status> ApplicationDaemon::ListSessions(const json &filter) {
  return m_impl->ListSessions(filter);
}

Result<json, Status> ApplicationDaemon::GetDaemonStats() {
  return m_impl->GetDaemonStats();
}

Result<json, Status> ApplicationDaemon::GetSessionHistory(size_t limit) {
  return m_impl->GetSessionHistory(limit);
}

Result<size_t, Status> ApplicationDaemon::RecoverState() {
  return m_impl->RecoverState();
}