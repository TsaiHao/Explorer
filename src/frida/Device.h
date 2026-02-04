//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#include "Session.h"
#include "nlohmann/json.hpp"
#include "utils/Macros.h"
#include "utils/SmallMap.h"
#include "utils/System.h"

#include <chrono>
#include <functional>
#include <mutex>
#include <string>

namespace frida {
class Device {
public:
  using EnumerateSessionCallback = std::function<bool(Session *session)>;

  Device();
  ~Device();

  DISABLE_COPY_AND_MOVE(Device);

  Status BuildSessionsFromConfig(const nlohmann::json &config);
  Status Resume();

  Status Attach(const utils::ProcessInfo &proc_info);
  Status Detach(const utils::ProcessInfo &proc_info);

  Status SpawnAppAndAttach(std::string_view exec_name,
                           const std::vector<std::string> &args = {});
  Status LaunchAppAndAttach(std::string_view am_command_args);

  Session *GetSession(pid_t target_pid) const;

  bool EnumerateSessions(const EnumerateSessionCallback &callback) const;

  // Enhanced session management for daemon mode
  /**
   * Create a new session from JSON configuration.
   * @param config JSON configuration for the session
   * @return Status and session info if successful
   */
  Result<nlohmann::json, Status> CreateSession(const nlohmann::json &config);

  /**
   * Create a new session with cancellation support.
   * @param config JSON configuration for the session
   * @param should_cancel Function that returns true if operation should be
   * cancelled
   * @return Status and session info if successful
   */
  Result<nlohmann::json, Status>
  CreateSessionWithCancellation(const nlohmann::json &config,
                                std::function<bool()> should_cancel);

  /**
   * Remove and stop a session by PID.
   * @param target_pid The PID of the session to remove
   * @return Status indicating success/failure
   */
  Status RemoveSession(pid_t target_pid);

  /**
   * Get detailed information about a session.
   * @param target_pid The PID of the session to query
   * @return Status and session information if found
   */
  Result<nlohmann::json, Status> GetSessionInfo(pid_t target_pid) const;

  /**
   * List all active sessions with optional filtering.
   * @param filter Optional filter criteria
   * @return Status and list of sessions
   */
  Result<nlohmann::json, Status> ListAllSessions(
      const nlohmann::json &filter = nlohmann::json::object()) const;

  /**
   * Drain cached messages from a session.
   * @param target_pid The PID of the session to drain messages from
   * @return JSON with drained messages and metadata
   */
  Result<nlohmann::json, Status> DrainSessionMessages(pid_t target_pid);

  /**
   * Get session statistics.
   * @return JSON object with session statistics
   */
  nlohmann::json GetSessionStatistics() const;

private:
  /**
   * Session metadata for tracking session information.
   */
  struct SessionMetadata {
    pid_t pid{0};
    std::string app_name;
    std::string session_status;
    std::chrono::system_clock::time_point created_at;
    nlohmann::json config;

    SessionMetadata() = default;

    SessionMetadata(pid_t p, std::string app, nlohmann::json cfg)
        : pid(p), app_name(std::move(app)), session_status("active"),
          created_at(std::chrono::system_clock::now()), config(std::move(cfg)) {
    }
  };

  Status BuildOneSessionFromConfig(const nlohmann::json &session_config);
  Status AttachToAppFromConfig(const nlohmann::json &session_config);

  // Helper methods for dynamic session management
  Status CreateSingleSession(const nlohmann::json &session_config);
  nlohmann::json SessionToJson(const Session *session,
                               const SessionMetadata &metadata) const;
  std::string ExtractAppNameFromConfig(const nlohmann::json &config) const;

  std::string m_name;
  FridaDevice *m_device{nullptr};
  FridaDeviceManager *m_manager{nullptr};

  std::vector<pid_t> m_pending_spawns;
  const nlohmann::json *m_config = nullptr;

  SmallMap<utils::ProcessInfo, std::unique_ptr<Session>> m_sessions;

  // Session metadata and thread safety
  mutable std::mutex m_sessions_mutex;
  SmallMap<pid_t, SessionMetadata> m_session_metadata;

  // Statistics
  mutable std::atomic<size_t> m_total_sessions_created{0};
  std::chrono::steady_clock::time_point m_device_created_at;
};
} // namespace frida
