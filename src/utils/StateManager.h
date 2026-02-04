#pragma once

#include "nlohmann/json.hpp"
#include "utils/Macros.h"
#include "utils/Result.h"
#include "utils/Status.h"

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace utils {

/**
 * Manages persistent state for the Explorer daemon.
 * Handles session state serialization, recovery, and statistics tracking.
 */
class StateManager {
public:
  /**
   * Session state information for persistence.
   */
  struct SessionState {
    pid_t pid;
    std::string app_name;
    std::string status; // "active", "stopped", "error"
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_updated;
    nlohmann::json config;       // Original session configuration
    nlohmann::json runtime_info; // Runtime information (trace counts, etc.)
    std::string error_message;   // Error details if status is "error"

    SessionState() = default;
    SessionState(pid_t p, const std::string &app, const nlohmann::json &cfg);

    // Serialization
    nlohmann::json ToJson() const;
    static SessionState FromJson(const nlohmann::json &json);
  };

  /**
   * Daemon statistics for monitoring.
   */
  struct DaemonStats {
    std::chrono::system_clock::time_point daemon_start_time;
    std::chrono::system_clock::time_point last_state_save;
    size_t total_sessions_created = 0;
    size_t active_sessions_count = 0;
    size_t failed_sessions_count = 0;
    size_t state_saves_count = 0;
    size_t state_loads_count = 0;
    size_t recovery_attempts = 0;
    size_t orphaned_sessions_cleaned = 0;

    nlohmann::json ToJson() const;
    static DaemonStats FromJson(const nlohmann::json &json);
  };

  explicit StateManager(const std::string &state_file_path =
                            "/data/local/tmp/explorer_state.json");
  ~StateManager();

  DISABLE_COPY_AND_MOVE(StateManager);

  /**
   * Initialize the state manager and attempt to load existing state.
   * @return Status indicating success or failure
   */
  Status Initialize();

  /**
   * Shutdown the state manager and save current state.
   * @return Status indicating success or failure
   */
  Status Shutdown();

  /**
   * Add or update a session in the persistent state.
   * @param session_state The session state to persist
   * @return Status indicating success or failure
   */
  Status SaveSessionState(const SessionState &session_state);

  /**
   * Remove a session from the persistent state.
   * @param pid The PID of the session to remove
   * @return Status indicating success or failure
   */
  Status RemoveSessionState(pid_t pid);

  /**
   * Get all active session states.
   * @return Vector of active session states
   */
  std::vector<SessionState> GetActiveSessionStates() const;

  /**
   * Get a specific session state by PID.
   * @param pid The PID to look for
   * @return Optional session state if found
   */
  std::optional<SessionState> GetSessionState(pid_t pid) const;

  /**
   * Update daemon statistics.
   * @param stats The updated daemon statistics
   * @return Status indicating success or failure
   */
  Status UpdateDaemonStats(const DaemonStats &stats);

  /**
   * Get current daemon statistics.
   * @return Current daemon statistics
   */
  DaemonStats GetDaemonStats() const;

  /**
   * Force a state save to disk.
   * @return Status indicating success or failure
   */
  Status FlushToDisk();

  /**
   * Perform recovery operations on daemon startup.
   * This includes cleaning up orphaned sessions and validating state.
   * @param cleanup_callback Callback for cleaning up orphaned sessions
   * @return Status indicating recovery success and number of sessions recovered
   */
  Result<size_t, Status>
  PerformRecovery(std::function<bool(pid_t)> cleanup_callback);

  /**
   * Get session history (last N sessions).
   * @param limit Maximum number of sessions to return (0 = no limit)
   * @return Vector of historical session states
   */
  std::vector<SessionState> GetSessionHistory(size_t limit = 100) const;

  /**
   * Clear old historical sessions to prevent state file from growing too large.
   * @param max_history_size Maximum number of historical sessions to keep
   * @return Number of sessions removed from history
   */
  size_t CleanupHistory(size_t max_history_size = 1000);

private:
  /**
   * Internal state representation.
   */
  struct InternalState {
    std::vector<SessionState> active_sessions;
    std::vector<SessionState> session_history;
    DaemonStats daemon_stats;
    std::chrono::system_clock::time_point state_version;

    nlohmann::json ToJson() const;
    static InternalState FromJson(const nlohmann::json &json);
  };

  /**
   * Load state from disk.
   * @return Status indicating success or failure
   */
  Status LoadFromDisk();

  /**
   * Save state to disk with atomic write.
   * @return Status indicating success or failure
   */
  Status SaveToDisk();

  /**
   * Acquire file lock for safe concurrent access.
   * @return Status indicating success or failure
   */
  Status AcquireFileLock();

  /**
   * Release file lock.
   */
  void ReleaseFileLock();

  /**
   * Validate and repair state consistency.
   * @return Status indicating validation result
   */
  Status ValidateAndRepairState();

  /**
   * Internal flush implementation; caller must already hold state_mutex_.
   */
  Status FlushToDiskLocked();

  std::string state_file_path_;
  mutable std::mutex state_mutex_;
  InternalState current_state_;

  // File locking support
  int lock_fd_;
  bool has_file_lock_;

  // Auto-save support
  std::chrono::steady_clock::time_point last_save_time_;
  bool dirty_state_;
  static constexpr int kAutoSaveIntervalSeconds = 30;
};

} // namespace utils