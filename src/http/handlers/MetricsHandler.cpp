#include "MetricsHandler.h"
#include "ApplicationDaemon.h"
#include "utils/Log.h"

#include <fstream>
#include <sys/times.h>
#include <unistd.h>

namespace http {

MetricsHandler::MetricsHandler(ApplicationDaemon *daemon)
    : EnhancedRequestHandler("MetricsHandler"), m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("MetricsHandler created with null ApplicationDaemon pointer");
  }
}

void MetricsHandler::ProcessRequest(Poco::Net::HTTPServerRequest &,
                                    Poco::Net::HTTPServerResponse &res,
                                    utils::RequestContext &context) {
  LOGI("Processing metrics request ({})", context.request_id);

  if (m_daemon == nullptr) {
    utils::ErrorInfo error(utils::ErrorCode::kDaemonNotInitialized,
                           "Daemon not available",
                           "ApplicationDaemon instance is null");
    SendError(res, error);
    return;
  }

  try {
    nlohmann::json metrics = CollectMetrics();
    SendSuccess(res, metrics, "Metrics collected successfully");

  } catch (const std::exception &e) {
    utils::ErrorInfo error(utils::ErrorCode::kInternalError,
                           "Metrics collection failed", e.what());
    SendError(res, error);
  }
}

nlohmann::json MetricsHandler::CollectMetrics() {
  auto collection_start = std::chrono::system_clock::now();

  nlohmann::json metrics = {
      {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                        collection_start.time_since_epoch())
                        .count()},
      {"service", "explorer-daemon"},
      {"metrics_version", "1.0"}};

  // Collect all metric categories
  metrics["daemon"] = GetDaemonMetrics();
  metrics["http_server"] = GetHttpServerMetrics();
  metrics["sessions"] = GetSessionMetrics();
  metrics["state_persistence"] = GetStatePersistenceMetrics();
  metrics["system"] = GetSystemMetrics();
  metrics["errors"] = GetErrorMetrics();

  // Add collection timing
  auto collection_end = std::chrono::system_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      collection_end - collection_start);
  metrics["collection_duration_ms"] = duration.count();

  return metrics;
}

nlohmann::json MetricsHandler::GetDaemonMetrics() {
  nlohmann::json daemon_metrics = {
      {"status", m_daemon->IsRunning() ? "running" : "stopped"},
      {"uptime_seconds", 0}};

  try {
    auto stats_result = m_daemon->GetDaemonStats();
    if (stats_result.IsOk()) {
      auto stats = stats_result.Unwrap();

      // Extract daemon start time and calculate uptime
      if (stats.contains("daemon_start_time")) {
        auto start_time_epoch = stats["daemon_start_time"].get<uint64_t>();
        auto current_time =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        daemon_metrics["uptime_seconds"] = current_time - start_time_epoch;
      }

      // Include all daemon statistics
      daemon_metrics.update(stats);
    }
  } catch (const std::exception &e) {
    daemon_metrics["error"] = e.what();
  }

  return daemon_metrics;
}

nlohmann::json MetricsHandler::GetHttpServerMetrics() {
  nlohmann::json http_metrics = {{"status", "running"}};

  try {
    // Get metrics from this handler (sample)
    auto handler_metrics = GetMetrics();
    http_metrics["handlers"] = nlohmann::json::object();
    http_metrics["handlers"]["MetricsHandler"] = handler_metrics;

    // TODO: Collect metrics from all registered handlers
    // This would require a registry of handlers in HttpServer

  } catch (const std::exception &e) {
    http_metrics["error"] = e.what();
  }

  return http_metrics;
}

nlohmann::json MetricsHandler::GetSessionMetrics() {
  nlohmann::json session_metrics = {
      {"active_count", 0}, {"total_created", 0}, {"failed_count", 0}};

  try {
    auto stats_result = m_daemon->GetDaemonStats();
    if (stats_result.IsOk()) {
      auto stats = stats_result.Unwrap();

      session_metrics["active_count"] = stats.value("active_sessions_count", 0);
      session_metrics["total_created"] =
          stats.value("total_sessions_created", 0);
      session_metrics["failed_count"] = stats.value("failed_sessions_count", 0);

      // Calculate success rate
      int total = session_metrics["total_created"];
      int failed = session_metrics["failed_count"];
      if (total > 0) {
        double success_rate =
            (static_cast<double>(total - failed) / total) * 100.0;
        session_metrics["success_rate_percent"] = success_rate;
      } else {
        session_metrics["success_rate_percent"] = 0.0;
      }

      // Add device statistics if available
      if (stats.contains("device_stats")) {
        session_metrics["device"] = stats["device_stats"];
      }
    }
  } catch (const std::exception &e) {
    session_metrics["error"] = e.what();
  }

  return session_metrics;
}

nlohmann::json MetricsHandler::GetStatePersistenceMetrics() {
  nlohmann::json state_metrics = {{"status", "unknown"},
                                  {"saves_count", 0},
                                  {"loads_count", 0},
                                  {"recovery_attempts", 0}};

  try {
    auto stats_result = m_daemon->GetDaemonStats();
    if (stats_result.IsOk()) {
      auto stats = stats_result.Unwrap();

      state_metrics["saves_count"] = stats.value("state_saves_count", 0);
      state_metrics["recovery_attempts"] = stats.value("recovery_attempts", 0);
      state_metrics["orphaned_cleaned"] =
          stats.value("orphaned_sessions_cleaned", 0);
      state_metrics["status"] = "operational";

      // Get session history metrics
      auto history_result = m_daemon->GetSessionHistory(0);
      if (history_result.IsOk()) {
        auto history = history_result.Unwrap();
        if (history.contains("total_count")) {
          state_metrics["history_size"] = history["total_count"];
        }
      }
    }
  } catch (const std::exception &e) {
    state_metrics["status"] = "error";
    state_metrics["error"] = e.what();
  }

  return state_metrics;
}

nlohmann::json MetricsHandler::GetSystemMetrics() {
  nlohmann::json system_metrics;

  try {
    // CPU usage
    struct tms cpu_times;
    clock_t uptime = times(&cpu_times);
    if (uptime != (clock_t)-1) {
      long clock_ticks = sysconf(_SC_CLK_TCK);
      if (clock_ticks > 0) {
        system_metrics["cpu"] = {
            {"user_time",
             static_cast<double>(cpu_times.tms_utime) / clock_ticks},
            {"system_time",
             static_cast<double>(cpu_times.tms_stime) / clock_ticks},
            {"uptime_seconds", static_cast<double>(uptime) / clock_ticks}};
      }
    }

    // Memory usage from /proc/self/status
    std::ifstream status("/proc/self/status");
    if (status.is_open()) {
      std::string line;
      while (std::getline(status, line)) {
        if (line.find("VmRSS:") == 0) {
          uint64_t rss_kb;
          if (sscanf(line.c_str(), "VmRSS: %llu kB", &rss_kb) == 1) {
            system_metrics["memory"]["resident_bytes"] = rss_kb * 1024;
          }
        } else if (line.find("VmSize:") == 0) {
          uint64_t size_kb;
          if (sscanf(line.c_str(), "VmSize: %llu kB", &size_kb) == 1) {
            system_metrics["memory"]["virtual_bytes"] = size_kb * 1024;
          }
        }
      }
    }

    // File descriptors
    system_metrics["file_descriptors"] = {{"current", 0},
                                          {"max", sysconf(_SC_OPEN_MAX)}};

    // Count current file descriptors
    try {
      int fd_count = 0;
      for (int fd = 0; fd < 1024; ++fd) {
        if (fcntl(fd, F_GETFD) != -1) {
          fd_count++;
        }
      }
      system_metrics["file_descriptors"]["current"] = fd_count;
    } catch (...) {
      // Ignore errors in FD counting
    }

  } catch (const std::exception &e) {
    system_metrics["error"] = e.what();
  }

  return system_metrics;
}

nlohmann::json MetricsHandler::GetErrorMetrics() {
  nlohmann::json error_metrics = {{"total_errors", 0},
                                  {"recent_errors", nlohmann::json::array()}};

  try {
    // Get handler-specific error metrics
    auto handler_metrics = GetMetrics();
    if (handler_metrics.contains("failed_requests")) {
      error_metrics["handler_errors"] = handler_metrics["failed_requests"];
    }

    // TODO: Implement error tracking system
    // This would maintain a circular buffer of recent errors
    // For now, we just indicate the structure

  } catch (const std::exception &e) {
    error_metrics["collection_error"] = e.what();
  }

  return error_metrics;
}

} // namespace http