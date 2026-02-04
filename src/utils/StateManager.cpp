#include "StateManager.h"
#include "utils/Log.h"
#include "utils/System.h"

#include <algorithm>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <signal.h>
#include <sstream>
#include <sys/file.h>
#include <unistd.h>
#include <unordered_set>

namespace utils {

namespace {

// Helper function to check if a process is still running
bool IsProcessRunning(pid_t pid) {
  if (pid <= 0)
    return false;
  return kill(pid, 0) == 0;
}

// Helper function to get current timestamp as ISO string
std::string
GetTimestampString(const std::chrono::system_clock::time_point &tp) {
  auto time_t = std::chrono::system_clock::to_time_t(tp);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// Helper function to parse timestamp from ISO string
std::chrono::system_clock::time_point
ParseTimestamp(const std::string &iso_string) {
  std::tm tm = {};
  std::istringstream ss(iso_string);
  ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

} // anonymous namespace

// SessionState implementation
StateManager::SessionState::SessionState(pid_t p, const std::string &app,
                                         const nlohmann::json &cfg)
    : pid(p), app_name(app), status("active"), config(cfg) {
  created_at = std::chrono::system_clock::now();
  last_updated = created_at;
}

nlohmann::json StateManager::SessionState::ToJson() const {
  nlohmann::json j = {{"pid", pid},
                      {"app_name", app_name},
                      {"status", status},
                      {"created_at", GetTimestampString(created_at)},
                      {"last_updated", GetTimestampString(last_updated)},
                      {"config", config},
                      {"runtime_info", runtime_info}};

  if (!error_message.empty()) {
    j["error_message"] = error_message;
  }

  return j;
}

StateManager::SessionState
StateManager::SessionState::FromJson(const nlohmann::json &j) {
  SessionState state;

  state.pid = j.value("pid", 0);
  state.app_name = j.value("app_name", "");
  state.status = j.value("status", "unknown");
  state.config = j.value("config", nlohmann::json::object());
  state.runtime_info = j.value("runtime_info", nlohmann::json::object());
  state.error_message = j.value("error_message", "");

  if (j.contains("created_at")) {
    state.created_at = ParseTimestamp(j["created_at"]);
  }
  if (j.contains("last_updated")) {
    state.last_updated = ParseTimestamp(j["last_updated"]);
  }

  return state;
}

// DaemonStats implementation
nlohmann::json StateManager::DaemonStats::ToJson() const {
  return nlohmann::json{
      {"daemon_start_time", GetTimestampString(daemon_start_time)},
      {"last_state_save", GetTimestampString(last_state_save)},
      {"total_sessions_created", total_sessions_created},
      {"active_sessions_count", active_sessions_count},
      {"failed_sessions_count", failed_sessions_count},
      {"state_saves_count", state_saves_count},
      {"state_loads_count", state_loads_count},
      {"recovery_attempts", recovery_attempts},
      {"orphaned_sessions_cleaned", orphaned_sessions_cleaned}};
}

StateManager::DaemonStats
StateManager::DaemonStats::FromJson(const nlohmann::json &j) {
  DaemonStats stats;

  if (j.contains("daemon_start_time")) {
    stats.daemon_start_time = ParseTimestamp(j["daemon_start_time"]);
  }
  if (j.contains("last_state_save")) {
    stats.last_state_save = ParseTimestamp(j["last_state_save"]);
  }

  stats.total_sessions_created = j.value("total_sessions_created", 0);
  stats.active_sessions_count = j.value("active_sessions_count", 0);
  stats.failed_sessions_count = j.value("failed_sessions_count", 0);
  stats.state_saves_count = j.value("state_saves_count", 0);
  stats.state_loads_count = j.value("state_loads_count", 0);
  stats.recovery_attempts = j.value("recovery_attempts", 0);
  stats.orphaned_sessions_cleaned = j.value("orphaned_sessions_cleaned", 0);

  return stats;
}

// InternalState implementation
nlohmann::json StateManager::InternalState::ToJson() const {
  nlohmann::json active_json = nlohmann::json::array();
  for (const auto &session : active_sessions) {
    active_json.push_back(session.ToJson());
  }

  nlohmann::json history_json = nlohmann::json::array();
  for (const auto &session : session_history) {
    history_json.push_back(session.ToJson());
  }

  return nlohmann::json{{"version", "1.0"},
                        {"state_version", GetTimestampString(state_version)},
                        {"active_sessions", active_json},
                        {"session_history", history_json},
                        {"daemon_stats", daemon_stats.ToJson()}};
}

StateManager::InternalState
StateManager::InternalState::FromJson(const nlohmann::json &j) {
  InternalState state;

  if (j.contains("state_version")) {
    state.state_version = ParseTimestamp(j["state_version"]);
  } else {
    state.state_version = std::chrono::system_clock::now();
  }

  if (j.contains("active_sessions") && j["active_sessions"].is_array()) {
    for (const auto &session_json : j["active_sessions"]) {
      state.active_sessions.push_back(SessionState::FromJson(session_json));
    }
  }

  if (j.contains("session_history") && j["session_history"].is_array()) {
    for (const auto &session_json : j["session_history"]) {
      state.session_history.push_back(SessionState::FromJson(session_json));
    }
  }

  if (j.contains("daemon_stats")) {
    state.daemon_stats = DaemonStats::FromJson(j["daemon_stats"]);
  }

  return state;
}

// StateManager implementation
StateManager::StateManager(const std::string &state_file_path)
    : state_file_path_(state_file_path), lock_fd_(-1), has_file_lock_(false),
      last_save_time_(std::chrono::steady_clock::now()), dirty_state_(false) {

  // Initialize daemon stats
  current_state_.daemon_stats.daemon_start_time =
      std::chrono::system_clock::now();
  current_state_.state_version = std::chrono::system_clock::now();

  LOGI("StateManager created for state file: {}", state_file_path_);
}

StateManager::~StateManager() {
  if (has_file_lock_) {
    // Save state before destruction
    if (dirty_state_) {
      auto save_status = SaveToDisk();
      if (!save_status.Ok()) {
        LOGE("Failed to save state during destruction: {}",
             save_status.Message());
      }
    }
    ReleaseFileLock();
  }
  LOGI("StateManager destroyed");
}

Status StateManager::Initialize() {
  std::lock_guard<std::mutex> lock(state_mutex_);

  LOGI("Initializing StateManager with state file: {}", state_file_path_);

  // Create state directory if it doesn't exist
  std::filesystem::path state_path(state_file_path_);
  std::filesystem::path state_dir = state_path.parent_path();

  if (!std::filesystem::exists(state_dir)) {
    std::error_code ec;
    if (!std::filesystem::create_directories(state_dir, ec)) {
      LOGE("Failed to create state directory {}: {}", state_dir.string(),
           ec.message());
      return SdkFailure("Failed to create state directory");
    }
  }

  // Acquire file lock
  auto lock_status = AcquireFileLock();
  if (!lock_status.Ok()) {
    return lock_status;
  }

  // Load existing state
  auto load_status = LoadFromDisk();
  if (!load_status.Ok()) {
    LOGW("Failed to load existing state (will start fresh): {}",
         load_status.Message());
    // Initialize fresh state
    current_state_ = InternalState{};
    current_state_.daemon_stats.daemon_start_time =
        std::chrono::system_clock::now();
    current_state_.state_version = std::chrono::system_clock::now();
  }

  // Validate and repair state consistency
  auto validation_status = ValidateAndRepairState();
  if (!validation_status.Ok()) {
    LOGW("State validation issues found: {}", validation_status.Message());
  }

  current_state_.daemon_stats.state_loads_count++;
  dirty_state_ = true;

  LOGI("StateManager initialized successfully");
  return Ok();
}

Status StateManager::Shutdown() {
  std::lock_guard<std::mutex> lock(state_mutex_);

  LOGI("Shutting down StateManager...");

  // Update shutdown timestamp
  current_state_.daemon_stats.last_state_save =
      std::chrono::system_clock::now();
  dirty_state_ = true;

  // Force save current state
  auto save_status = SaveToDisk();
  if (!save_status.Ok()) {
    LOGE("Failed to save state during shutdown: {}", save_status.Message());
  }

  // Release file lock
  ReleaseFileLock();

  LOGI("StateManager shutdown complete");
  return save_status;
}

Status StateManager::SaveSessionState(const SessionState &session_state) {
  std::lock_guard<std::mutex> lock(state_mutex_);

  // Find existing session or add new one
  auto it = std::find_if(current_state_.active_sessions.begin(),
                         current_state_.active_sessions.end(),
                         [&](const SessionState &existing) {
                           return existing.pid == session_state.pid;
                         });

  if (it != current_state_.active_sessions.end()) {
    // Update existing session
    *it = session_state;
    it->last_updated = std::chrono::system_clock::now();
    LOGI("Updated session state for PID {}", session_state.pid);
  } else {
    // Add new session
    current_state_.active_sessions.push_back(session_state);
    current_state_.daemon_stats.total_sessions_created++;
    LOGI("Added new session state for PID {}", session_state.pid);
  }

  current_state_.daemon_stats.active_sessions_count =
      current_state_.active_sessions.size();
  if (session_state.status == "error") {
    current_state_.daemon_stats.failed_sessions_count++;
  }

  dirty_state_ = true;

  // Auto-save if enough time has passed
  auto now = std::chrono::steady_clock::now();
  auto elapsed =
      std::chrono::duration_cast<std::chrono::seconds>(now - last_save_time_);
  if (elapsed.count() >= kAutoSaveIntervalSeconds) {
    return FlushToDiskLocked();
  }

  return Ok();
}

Status StateManager::RemoveSessionState(pid_t pid) {
  std::lock_guard<std::mutex> lock(state_mutex_);

  auto it = std::find_if(
      current_state_.active_sessions.begin(),
      current_state_.active_sessions.end(),
      [pid](const SessionState &session) { return session.pid == pid; });

  if (it != current_state_.active_sessions.end()) {
    // Move to history before removing
    SessionState historical_session = *it;
    historical_session.status = "stopped";
    historical_session.last_updated = std::chrono::system_clock::now();
    current_state_.session_history.push_back(historical_session);

    // Remove from active sessions
    current_state_.active_sessions.erase(it);
    current_state_.daemon_stats.active_sessions_count =
        current_state_.active_sessions.size();

    dirty_state_ = true;

    LOGI("Removed session state for PID {} (moved to history)", pid);
    return Ok();
  }

  LOGW("Attempted to remove non-existent session state for PID {}", pid);
  return NotFound("Session state not found");
}

std::vector<StateManager::SessionState>
StateManager::GetActiveSessionStates() const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return current_state_.active_sessions;
}

std::optional<StateManager::SessionState>
StateManager::GetSessionState(pid_t pid) const {
  std::lock_guard<std::mutex> lock(state_mutex_);

  auto it = std::find_if(
      current_state_.active_sessions.begin(),
      current_state_.active_sessions.end(),
      [pid](const SessionState &session) { return session.pid == pid; });

  if (it != current_state_.active_sessions.end()) {
    return *it;
  }

  return std::nullopt;
}

Status StateManager::UpdateDaemonStats(const DaemonStats &stats) {
  std::lock_guard<std::mutex> lock(state_mutex_);
  current_state_.daemon_stats = stats;
  dirty_state_ = true;
  return Ok();
}

StateManager::DaemonStats StateManager::GetDaemonStats() const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return current_state_.daemon_stats;
}

Status StateManager::FlushToDisk() {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return FlushToDiskLocked();
}

Status StateManager::FlushToDiskLocked() {
  if (!dirty_state_) {
    return Ok(); // No changes to save
  }

  auto save_status = SaveToDisk();
  if (save_status.Ok()) {
    dirty_state_ = false;
    last_save_time_ = std::chrono::steady_clock::now();
    current_state_.daemon_stats.state_saves_count++;
  }

  return save_status;
}

Result<size_t, Status>
StateManager::PerformRecovery(std::function<bool(pid_t)> cleanup_callback) {
  std::lock_guard<std::mutex> lock(state_mutex_);

  LOGI("Performing daemon recovery operations...");

  current_state_.daemon_stats.recovery_attempts++;

  size_t sessions_recovered = 0;
  size_t sessions_cleaned = 0;

  // Check all active sessions and clean up orphaned ones
  auto it = current_state_.active_sessions.begin();
  while (it != current_state_.active_sessions.end()) {
    bool is_running = IsProcessRunning(it->pid);

    if (!is_running) {
      // Process is no longer running - it's orphaned
      LOGW("Found orphaned session for PID {} ({})", it->pid, it->app_name);

      // Try to clean up using the provided callback
      bool cleaned_up = false;
      if (cleanup_callback) {
        try {
          cleaned_up = cleanup_callback(it->pid);
        } catch (const std::exception &e) {
          LOGE("Exception during cleanup callback for PID {}: {}", it->pid,
               e.what());
        }
      }

      // Move to history as failed/orphaned
      SessionState orphaned_session = *it;
      orphaned_session.status = "orphaned";
      orphaned_session.error_message = "Process no longer running (orphaned)";
      orphaned_session.last_updated = std::chrono::system_clock::now();
      current_state_.session_history.push_back(orphaned_session);

      // Remove from active sessions
      it = current_state_.active_sessions.erase(it);
      sessions_cleaned++;
      current_state_.daemon_stats.orphaned_sessions_cleaned++;

      if (cleaned_up) {
        LOGI("Successfully cleaned up orphaned session for PID {}",
             orphaned_session.pid);
      } else {
        LOGW("Failed to clean up orphaned session for PID {}",
             orphaned_session.pid);
      }
    } else {
      // Session is still active
      sessions_recovered++;
      it->status = "recovered";
      it->last_updated = std::chrono::system_clock::now();
      ++it;
    }
  }

  // Update statistics
  current_state_.daemon_stats.active_sessions_count =
      current_state_.active_sessions.size();
  dirty_state_ = true;

  LOGI(
      "Recovery completed: {} sessions recovered, {} orphaned sessions cleaned",
      sessions_recovered, sessions_cleaned);

  return Ok<size_t>(sessions_recovered);
}

std::vector<StateManager::SessionState>
StateManager::GetSessionHistory(size_t limit) const {
  std::lock_guard<std::mutex> lock(state_mutex_);

  if (limit == 0 || current_state_.session_history.size() <= limit) {
    return current_state_.session_history;
  }

  // Return the most recent N sessions
  auto start = current_state_.session_history.end() - limit;
  return std::vector<SessionState>(start, current_state_.session_history.end());
}

size_t StateManager::CleanupHistory(size_t max_history_size) {
  std::lock_guard<std::mutex> lock(state_mutex_);

  if (current_state_.session_history.size() <= max_history_size) {
    return 0;
  }

  size_t sessions_to_remove =
      current_state_.session_history.size() - max_history_size;

  // Remove oldest sessions
  current_state_.session_history.erase(current_state_.session_history.begin(),
                                       current_state_.session_history.begin() +
                                           sessions_to_remove);

  dirty_state_ = true;

  LOGI("Cleaned up {} old sessions from history (keeping {} most recent)",
       sessions_to_remove, max_history_size);

  return sessions_to_remove;
}

Status StateManager::LoadFromDisk() {
  if (!std::filesystem::exists(state_file_path_)) {
    LOGI("State file does not exist, starting with fresh state");
    return Ok();
  }

  std::ifstream file(state_file_path_);
  if (!file.is_open()) {
    return SdkFailure("Failed to open state file for reading");
  }

  nlohmann::json state_json;
  try {
    file >> state_json;
  } catch (const nlohmann::json::exception &e) {
    LOGE("Failed to parse state JSON: {}", e.what());
    return BadArgument("Invalid state file format");
  }

  try {
    current_state_ = InternalState::FromJson(state_json);
    LOGI("Successfully loaded state from disk: {} active sessions, {} "
         "historical sessions",
         current_state_.active_sessions.size(),
         current_state_.session_history.size());
  } catch (const std::exception &e) {
    LOGE("Failed to deserialize state: {}", e.what());
    return SdkFailure("State deserialization failed");
  }

  return Ok();
}

Status StateManager::SaveToDisk() {
  try {
    // Update state version timestamp
    current_state_.state_version = std::chrono::system_clock::now();
    current_state_.daemon_stats.last_state_save = current_state_.state_version;

    // Serialize to JSON
    nlohmann::json state_json = current_state_.ToJson();

    // Write atomically using temporary file
    std::string temp_file = state_file_path_ + ".tmp";
    std::ofstream file(temp_file);
    if (!file.is_open()) {
      return SdkFailure("Failed to open temporary state file for writing");
    }

    file << state_json.dump(2); // Pretty-print with 2-space indentation
    file.close();

    if (!file.good()) {
      std::filesystem::remove(temp_file);
      return SdkFailure("Failed to write state to temporary file");
    }

    // Atomic rename
    if (std::rename(temp_file.c_str(), state_file_path_.c_str()) != 0) {
      std::filesystem::remove(temp_file);
      return SdkFailure("Failed to rename temporary state file");
    }

    LOGI("Successfully saved state to disk: {} active sessions, {} historical "
         "sessions",
         current_state_.active_sessions.size(),
         current_state_.session_history.size());

  } catch (const std::exception &e) {
    LOGE("Exception during state save: {}", e.what());
    return SdkFailure("State serialization failed");
  }

  return Ok();
}

Status StateManager::AcquireFileLock() {
  lock_fd_ = open(state_file_path_.c_str(), O_CREAT | O_RDWR, 0644);
  if (lock_fd_ == -1) {
    LOGE("Failed to open state file for locking: {}", strerror(errno));
    return SdkFailure("Failed to open state file for locking");
  }

  // Try to acquire exclusive lock (non-blocking)
  if (flock(lock_fd_, LOCK_EX | LOCK_NB) == -1) {
    if (errno == EAGAIN || errno == EACCES) {
      close(lock_fd_);
      lock_fd_ = -1;
      return SdkFailure(
          "Another daemon instance is already using the state file");
    } else {
      LOGE("Failed to acquire file lock: {}", strerror(errno));
      close(lock_fd_);
      lock_fd_ = -1;
      return SdkFailure("Failed to acquire file lock");
    }
  }

  has_file_lock_ = true;
  LOGI("Successfully acquired file lock for state file");
  return Ok();
}

void StateManager::ReleaseFileLock() {
  if (lock_fd_ != -1) {
    flock(lock_fd_, LOCK_UN);
    close(lock_fd_);
    lock_fd_ = -1;
    has_file_lock_ = false;
    LOGI("Released file lock for state file");
  }
}

Status StateManager::ValidateAndRepairState() {
  // Remove any duplicate sessions (same PID)
  std::unordered_set<pid_t> seen_pids;
  auto it = current_state_.active_sessions.begin();
  while (it != current_state_.active_sessions.end()) {
    if (seen_pids.find(it->pid) != seen_pids.end()) {
      LOGW("Removing duplicate session for PID {}", it->pid);
      it = current_state_.active_sessions.erase(it);
    } else {
      seen_pids.insert(it->pid);
      ++it;
    }
  }

  // Validate session data integrity
  for (auto &session : current_state_.active_sessions) {
    if (session.pid <= 0) {
      LOGW("Invalid PID {} in session state", session.pid);
      session.status = "error";
      session.error_message = "Invalid PID";
    }
    if (session.app_name.empty()) {
      LOGW("Empty app name for PID {}", session.pid);
      session.app_name = "unknown";
    }
  }

  // Update active sessions count
  current_state_.daemon_stats.active_sessions_count =
      current_state_.active_sessions.size();

  LOGI("State validation completed");
  return Ok();
}

} // namespace utils