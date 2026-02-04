#include "HealthHandler.h"
#include "ApplicationDaemon.h"
#include "utils/Log.h"

#include <fstream>
#include <sys/statvfs.h>
#include <unistd.h>

namespace http {

HealthHandler::HealthHandler(ApplicationDaemon *daemon)
    : EnhancedRequestHandler("HealthHandler"), m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("HealthHandler created with null ApplicationDaemon pointer");
  }
}

void HealthHandler::ProcessRequest(Poco::Net::HTTPServerRequest &,
                                   Poco::Net::HTTPServerResponse &res,
                                   utils::RequestContext &context) {
  LOGI("Processing health check request ({})", context.request_id);

  if (m_daemon == nullptr) {
    utils::ErrorInfo error(utils::ErrorCode::kDaemonNotInitialized,
                           "Daemon not available",
                           "ApplicationDaemon instance is null");
    SendError(res, error);
    return;
  }

  try {
    nlohmann::json health_data = PerformHealthChecks();

    // Determine overall health status
    bool is_healthy = true;
    std::string status = "healthy";

    // Check if any component is unhealthy
    for (const auto &[component, info] : health_data["components"].items()) {
      if (info.contains("status") && info["status"] != "healthy") {
        is_healthy = false;
        status = "unhealthy";
        break;
      }
    }

    health_data["status"] = status;
    health_data["healthy"] = is_healthy;

    // Send response with appropriate status
    if (is_healthy) {
      SendSuccess(res, health_data, "Service is healthy");
    } else {
      res.setStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);
      res.setContentType("application/json");

      json error_response = {{"status", "error"},
                             {"message", "Service has health issues"},
                             {"data", health_data}};

      std::string response_str = error_response.dump(2);
      res.setContentLength(response_str.length());

      std::ostream &out = res.send();
      out << response_str;
    }

  } catch (const std::exception &e) {
    utils::ErrorInfo error(utils::ErrorCode::kInternalError,
                           "Health check failed", e.what());
    SendError(res, error);
  }
}

nlohmann::json HealthHandler::PerformHealthChecks() {
  auto start_time = std::chrono::system_clock::now();

  nlohmann::json health_data = {
      {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                        start_time.time_since_epoch())
                        .count()},
      {"service", "explorer-daemon"},
      {"version", "1.0.0"}, // TODO: Get from version.h
      {"components", nlohmann::json::object()}};

  // Check daemon status
  health_data["components"]["daemon"] = {
      {"status", m_daemon->IsRunning() ? "healthy" : "unhealthy"},
      {"running", m_daemon->IsRunning()}};

  // Check FRIDA system
  health_data["components"]["frida"] = CheckFridaHealth();

  // Check state manager
  health_data["components"]["state_manager"] = CheckStateManagerHealth();

  // Check HTTP server
  health_data["components"]["http_server"] = CheckHttpServerHealth();

  // Check system resources
  health_data["components"]["system"] = CheckSystemResources();

  auto end_time = std::chrono::system_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  health_data["check_duration_ms"] = duration.count();

  return health_data;
}

nlohmann::json HealthHandler::CheckFridaHealth() {
  nlohmann::json frida_health = {{"status", "healthy"}, {"initialized", true}};

  try {
    // Basic FRIDA health check - try to get daemon stats which uses device
    auto stats_result = m_daemon->GetDaemonStats();
    if (stats_result.IsOk()) {
      auto stats = stats_result.Unwrap();
      frida_health["active_sessions"] = stats.value("active_sessions_count", 0);
      frida_health["total_sessions"] = stats.value("total_sessions_created", 0);
    } else {
      frida_health["status"] = "degraded";
      frida_health["error"] = stats_result.UnwrapErr().Message();
    }
  } catch (const std::exception &e) {
    frida_health["status"] = "unhealthy";
    frida_health["error"] = e.what();
    frida_health["initialized"] = false;
  }

  return frida_health;
}

nlohmann::json HealthHandler::CheckStateManagerHealth() {
  nlohmann::json state_health = {{"status", "healthy"}, {"initialized", true}};

  try {
    // Try to get daemon stats to test state manager
    auto stats_result = m_daemon->GetDaemonStats();
    if (stats_result.IsOk()) {
      auto stats = stats_result.Unwrap();
      state_health["state_saves"] = stats.value("state_saves_count", 0);
      state_health["recovery_attempts"] = stats.value("recovery_attempts", 0);
    } else {
      state_health["status"] = "degraded";
      state_health["error"] = stats_result.UnwrapErr().Message();
    }
  } catch (const std::exception &e) {
    state_health["status"] = "unhealthy";
    state_health["error"] = e.what();
    state_health["initialized"] = false;
  }

  return state_health;
}

nlohmann::json HealthHandler::CheckHttpServerHealth() {
  nlohmann::json http_health = {{"status", "healthy"}, {"running", true}};

  // If we're able to process this request, HTTP server is running
  // Additional checks could be added here for thread pool status, etc.

  return http_health;
}

nlohmann::json HealthHandler::CheckSystemResources() {
  nlohmann::json system_health = {{"status", "healthy"}};

  try {
    // Check disk space for state directory
    struct statvfs stat_buf;
    if (statvfs("/data/local/tmp", &stat_buf) == 0) {
      uint64_t free_space =
          static_cast<uint64_t>(stat_buf.f_bavail) * stat_buf.f_frsize;
      uint64_t total_space =
          static_cast<uint64_t>(stat_buf.f_blocks) * stat_buf.f_frsize;
      double usage_percent =
          (1.0 - (static_cast<double>(free_space) / total_space)) * 100.0;

      system_health["disk"] = {{"free_bytes", free_space},
                               {"total_bytes", total_space},
                               {"usage_percent", usage_percent}};

      if (usage_percent > 95.0) {
        system_health["status"] = "unhealthy";
        system_health["disk"]["warning"] = "Disk space critically low";
      } else if (usage_percent > 85.0) {
        system_health["status"] = "degraded";
        system_health["disk"]["warning"] = "Disk space running low";
      }
    }

    // Check memory usage (simplified)
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
      std::string line;
      uint64_t mem_total = 0, mem_available = 0;

      while (std::getline(meminfo, line)) {
        if (line.find("MemTotal:") == 0) {
          sscanf(line.c_str(), "MemTotal: %llu kB", &mem_total);
          mem_total *= 1024; // Convert to bytes
        } else if (line.find("MemAvailable:") == 0) {
          sscanf(line.c_str(), "MemAvailable: %llu kB", &mem_available);
          mem_available *= 1024; // Convert to bytes
        }
      }

      if (mem_total > 0 && mem_available > 0) {
        double memory_usage =
            (1.0 - (static_cast<double>(mem_available) / mem_total)) * 100.0;

        system_health["memory"] = {{"total_bytes", mem_total},
                                   {"available_bytes", mem_available},
                                   {"usage_percent", memory_usage}};

        if (memory_usage > 95.0) {
          system_health["status"] = "unhealthy";
          system_health["memory"]["warning"] = "Memory usage critically high";
        } else if (memory_usage > 85.0) {
          system_health["status"] = "degraded";
          system_health["memory"]["warning"] = "Memory usage high";
        }
      }
    }

    // Check load average
    std::ifstream loadavg("/proc/loadavg");
    if (loadavg.is_open()) {
      float load1, load5, load15;
      loadavg >> load1 >> load5 >> load15;

      system_health["load_average"] = {
          {"1min", load1}, {"5min", load5}, {"15min", load15}};

      // Get number of CPU cores for load comparison
      long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
      if (nprocs > 0) {
        system_health["cpu_cores"] = nprocs;

        // Load average warning if > number of cores
        if (load1 > nprocs * 2) {
          system_health["status"] = "degraded";
          system_health["load_average"]["warning"] = "High system load";
        }
      }
    }

  } catch (const std::exception &e) {
    system_health["status"] = "degraded";
    system_health["error"] = e.what();
  }

  return system_health;
}

} // namespace http