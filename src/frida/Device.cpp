//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Device.h"
#include "frida-core.h"
#include "utils/Log.h"
#include "utils/Status.h"
#include "utils/Subprocess.h"
#include "utils/System.h"
#include "utils/Util.h"

namespace frida {
namespace {
constexpr std::string_view kAppNameKey = "app";
constexpr std::string_view kPidKey = "pid";
constexpr std::string_view kAmStartKey = "am_start";
constexpr std::string_view kSpawnKey = "spawn";

class DeviceSpawnGatingGuard {
public:
  explicit DeviceSpawnGatingGuard(FridaDevice *device) : m_device(device) {
    CHECK(m_device != nullptr);
    GError *error = nullptr;
    frida_device_enable_spawn_gating_sync(m_device, nullptr, &error);
    if (error != nullptr) {
      LOGE("Failed to enable spawn gating: {}", error->message);
    }
    m_enabled = (error == nullptr);
  }

  ~DeviceSpawnGatingGuard() {
    if (m_enabled) {
      GError *error = nullptr;
      frida_device_disable_spawn_gating_sync(m_device, nullptr, &error);
      if (error != nullptr) {
        LOGE("Failed to disable spawn gating: {}", error->message);
      }
    }
  }

  bool IsEnabled() const { return m_enabled; }

private:
  FridaDevice *m_device = nullptr;
  bool m_enabled = false;
};

std::optional<std::string_view>
ExtractAppNameFromAmCommand(std::string_view am_command) {
  // am_command is expected to be in the format:
  // "am start <other_options> -n <package_name>/<activity_name> <args>"
  auto dash_n_pos = am_command.find("-n ");
  if (dash_n_pos == std::string_view::npos) {
    return std::nullopt;
  }
  dash_n_pos += 3; // Move past "-n "

  auto slash_pos = am_command.find('/', dash_n_pos);
  if (slash_pos == std::string_view::npos) {
    return std::nullopt;
  }
  auto package_name = am_command.substr(dash_n_pos, slash_pos - dash_n_pos);
  return package_name;
}

int64_t GetNowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

void KillAppIfRunning(std::string_view app_name) {
  auto proc_info = utils::FindProcessByName(app_name);
  if (!proc_info.has_value()) {
    return;
  }

  LOGI("App {} is running, attempting to kill it with PID: {}", app_name,
       proc_info->pid);

  int ret = kill(proc_info->pid, SIGTERM);
  if (ret != 0) {
    LOGE("Failed to kill app {} with PID: {}", app_name, proc_info->pid);
  } else {
    LOGI("Successfully killed app {} with PID: {}", app_name, proc_info->pid);
  }
}
} // namespace

Device::Device() : m_device_created_at(std::chrono::steady_clock::now()) {
  LOGI("Creating frida device {}", (void *)this);

  m_manager = frida_device_manager_new();
  CHECK(m_manager != nullptr);

  GError *error = nullptr;
  auto *devices =
      frida_device_manager_enumerate_devices_sync(m_manager, nullptr, &error);
  CHECK(error == nullptr);

  const auto n_devices = frida_device_list_size(devices);
  for (int i = 0; i < n_devices; ++i) {
    auto *device = frida_device_list_get(devices, i);
    LOGD("Found device {}", (void *)frida_device_get_name(device));

    if (frida_device_get_dtype(device) == FRIDA_DEVICE_TYPE_LOCAL) {
      m_device = g_object_ref(device);
      m_name = frida_device_get_name(device);
    }

    g_object_unref(device);
  }

  if (m_device == nullptr) {
    LOGE("No valid device found, current device list:");
    for (int i = 0; i < n_devices; ++i) {
      auto *device = frida_device_list_get(devices, i);
      LOGE("Device {}", frida_device_get_name(device));
    }
  }

  frida_unref(devices);
}

Device::~Device() {
  LOGI("Destroying frida device {}@{}", m_name, (void *)this);

  if (m_device != nullptr) {
    frida_unref(m_device);
    m_device = nullptr;
  }
  if (m_manager != nullptr) {
    frida_device_manager_close_sync(m_manager, nullptr, nullptr);
    frida_unref(m_manager);
    m_manager = nullptr;
  }
}

Status Device::BuildSessionsFromConfig(const nlohmann::json &config) {
  CHECK(m_device != nullptr);
  CHECK(config.is_array());
  m_config = &config;

  for (const auto &session_config : config) {
    Status status = BuildOneSessionFromConfig(session_config);
    if (!status.Ok()) {
      return status;
    }
  }

  return Ok();
}

Status Device::Resume() {
  LOGI("Resuming frida device {}@{}", m_name, (void *)this);

  CHECK(m_device != nullptr);

  for (const auto &pid : m_pending_spawns) {
    GError *error = nullptr;
    frida_device_resume_sync(m_device, pid, nullptr, &error);
    if (error != nullptr) {
      // LOG(ERROR) << "Error resuming frida device: " << error->message;
      g_error_free(error);
      // todo: fix this "Invalid PID" error
      // return SdkFailure("frida resume api failed");
    }
  }

  m_pending_spawns.clear();
  return Ok();
}

Status Device::Attach(const utils::ProcessInfo &proc_info) {
  LOGI("Attaching frida device {}@{} targeting {}", m_name, (void *)this,
       proc_info.cmd_line);

  CHECK(m_device != nullptr);
  if (m_sessions.Contains(proc_info) && m_sessions.At(proc_info) != nullptr) {
    LOGI("Already attached to process {}({})", proc_info.cmd_line,
         proc_info.pid);
    return InvalidOperation("Multiple attachments");
  }

  GError *error = nullptr;

  auto *session = frida_device_attach_sync(m_device, proc_info.pid, nullptr,
                                           nullptr, &error);
  if (error != nullptr) {
    LOGE("Error attaching frida device: {}", error->message);
    frida_unref(session);

    return SdkFailure("frida attach api failed");
  }

  m_sessions[proc_info] = std::make_unique<Session>(proc_info.pid, session);

  return Ok();
}

// todo: is this resume-able?
Status Device::Detach(const utils::ProcessInfo &proc_info) {
  LOGI("Detaching frida device {}@{} targeting {}({})", m_name, (void *)this,
       proc_info.cmd_line, proc_info.pid);

  CHECK(m_device != nullptr);
  CHECK(m_sessions.Contains(proc_info));

  m_sessions.Erase(proc_info);
  return Ok();
}

Status Device::SpawnAppAndAttach(std::string_view exec_name,
                                 const std::vector<std::string> &args) {
  LOGI("Spawning and attaching to app {}", exec_name);

  CHECK(m_device != nullptr);

  GError *error = nullptr;
  FridaSpawnOptions *options = frida_spawn_options_new();
  if (!args.empty()) {
    std::vector<char *> argv(args.size());
    for (size_t i = 0; i < args.size(); ++i) {
      argv[i] = const_cast<char *>(args[i].c_str());
    }
    frida_spawn_options_set_argv(options, argv.data(),
                                 static_cast<int>(argv.size()));
  }
  auto spawn_pid = frida_device_spawn_sync(m_device, exec_name.data(), options,
                                           nullptr, &error);

  frida_unref(options);

  LOGI("Spawned app with PID: {}", spawn_pid);
  if (error != nullptr) {
    LOGE("Error spawning app: {}", error->message);
    g_error_free(error);
    return SdkFailure("frida spawn api failed");
  }
  if (spawn_pid <= 0) {
    LOGE("Invalid PID returned from frida spawn: {}", spawn_pid);
    return SdkFailure("frida spawn returned invalid PID");
  }

  m_pending_spawns.push_back(static_cast<pid_t>(spawn_pid));

  utils::SleepForMilliseconds(2000);

  auto proc_info = utils::FindProcessByPid(static_cast<pid_t>(spawn_pid));
  if (!proc_info.has_value()) {
    LOGE("Failed to find process by PID: {}", spawn_pid);
    return NotFound("Process not found by PID");
  }

  return Attach(*proc_info);
}

Status Device::LaunchAppAndAttach(std::string_view am_command_args) {
  // Assuming the am_command_args is space separated arguments
  LOGI("Launching app with am command: {}", am_command_args);

  CHECK(m_device != nullptr);
  GError *error = nullptr;

  auto args = utils::SplitString(am_command_args, " ");
  if (args.empty()) {
    LOGE("No arguments provided for am command");
    return BadArgument("No arguments provided for am command");
  }

  utils::Subprocess am_process;
  DeviceSpawnGatingGuard guard(m_device);
  CHECK(guard.IsEnabled());

  Status status = am_process.Spawn("sh", {"-c", std::string(am_command_args)});
  if (!status.Ok()) {
    LOGE("Failed to spawn am command: {}", status.Message());
    return status;
  }

  auto result = am_process.Wait(10000);
  if (result.timed_out) {
    LOGE("AM command timed out");
    return InvalidOperation("AM command timed out");
  }
  if (result.exit_status != 0) {
    LOGE("AM command failed with exit status: {}, stderr: {}",
         result.exit_status, result.stderr);
    return SdkFailure("AM command failed: " + result.stderr);
  }

  constexpr int64_t kWaitForAppLaunchTimeoutMs = 10000;
  auto package_name = ExtractAppNameFromAmCommand(am_command_args);
  if (!package_name.has_value()) {
    LOGE("Failed to extract package name from AM command: {}", am_command_args);
    return BadArgument("Failed to extract package name from AM command");
  }
  LOGI("Extracted package name: {}", *package_name);

  int64_t start_time = GetNowMs();
  while (true) {
    FridaSpawnList *spawned_apps =
        frida_device_enumerate_pending_spawn_sync(m_device, nullptr, &error);
    if (error != nullptr) {
      LOGE("Error enumerating pending spawns: {}", error->message);
      return SdkFailure("frida enumerate pending spawn failed");
    }

    bool found = false;
    for (int i = 0; i < frida_spawn_list_size(spawned_apps); ++i) {
      auto *spawn = frida_spawn_list_get(spawned_apps, i);
      auto const *identifier = frida_spawn_get_identifier(spawn);
      auto pid = frida_spawn_get_pid(spawn);

      LOGD("Found pending spawn: {}(PID: {})", identifier, pid);
      if (identifier == *package_name) {
        found = true;
        LOGI("Found pending spawn with PID: {}", pid);
        frida_unref(spawned_apps);
        frida_unref(spawn);

        m_pending_spawns.push_back(static_cast<pid_t>(pid));
        auto proc_info = utils::FindProcessByPid(static_cast<pid_t>(pid));
        if (!proc_info.has_value()) {
          LOGE("Failed to find process by PID: {}", pid);
          return NotFound("Process not found by PID");
        }
        return Attach(*proc_info);
      }

      frida_device_resume_sync(m_device, pid, nullptr, &error);
      if (error != nullptr) {
        LOGE("Error resuming spawn with PID {}: {}", pid, error->message);
        return SdkFailure("frida resume spawn failed");
      }

      frida_unref(spawn);
    }
    frida_unref(spawned_apps);

    if (found) {
      break;
    }
    if (GetNowMs() - start_time > kWaitForAppLaunchTimeoutMs) {
      return Timeout("Timed out waiting for app to launch");
    }
  }
#ifdef EXP_DEBUG
  LOGI("AM command executed successfully, stdout: {}", result.stdout);
#endif

  return Ok();
}

Session *Device::GetSession(pid_t target_pid) const {
  Session *session = nullptr;

  m_sessions.ForEach(
      [&target_pid, &session](const utils::ProcessInfo &proc_info,
                              const std::unique_ptr<Session> &s) {
        if (proc_info.pid == target_pid) {
          session = s.get();
          return;
        }
      });

  return session;
}

bool Device::EnumerateSessions(const EnumerateSessionCallback &callback) const {
  for (auto it = m_sessions.CBegin(); it != m_sessions.CEnd(); ++it) {
    const auto &session = it->second.get();
    if (callback(session)) {
      return true;
    }
  }
  return false;
}

Status Device::BuildOneSessionFromConfig(const nlohmann::json &session_config) {
  Status status = AttachToAppFromConfig(session_config);
  if (!status.Ok()) {
    LOGE("Failed to attach to app from config: {}", status.Message());
    return status;
  }

  // todo: fix this temporary workaround
  Session *session = m_sessions.Back().second.get();
  CHECK(session != nullptr);

  CHECK_STATUS(session->LoadInlineScriptsFromConfig(session_config));
  CHECK_STATUS(session->LoadScriptFilesFromConfig(session_config));
  CHECK_STATUS(session->LoadPlugins(session_config));

  return Ok();
}

Status Device::AttachToAppFromConfig(const nlohmann::json &session_config) {
  const std::string app_name = session_config[kAppNameKey].get<std::string>();

  if (session_config.contains(kAmStartKey)) {
    const std::string am_command =
        session_config[kAmStartKey].get<std::string>();
    CHECK(!am_command.empty());
    KillAppIfRunning(app_name);
    return LaunchAppAndAttach(am_command);
  }

  if (session_config.contains(kSpawnKey)) {
    const bool need_spawn = session_config[kSpawnKey].get<bool>();
    if (need_spawn) {
      CHECK(!app_name.empty());
      KillAppIfRunning(app_name);
      return SpawnAppAndAttach(app_name);
    }
  }

  if (session_config.contains(kPidKey)) {
    int const pid = session_config[kPidKey].get<int>();
    if (const auto proc = utils::FindProcessByPid(pid); proc.has_value()) {
      return Attach(*proc);
    }
    return NotFound("Process not found");
  }

  if (session_config.contains(kAppNameKey)) {
    std::string const app_name = session_config[kAppNameKey].get<std::string>();
    if (const auto proc = utils::FindProcessByName(app_name);
        proc.has_value()) {
      return Attach(*proc);
    }
    return NotFound("Process not found");
  }

  return BadArgument("No PID or app name provided");
}

// Enhanced session management methods for daemon mode

Result<nlohmann::json, Status>
Device::CreateSession(const nlohmann::json &config) {
  std::lock_guard<std::mutex> lock(m_sessions_mutex);

  LOGI("Creating new session with config: {}", config.dump());

  // Validate configuration
  if (!config.is_object()) {
    return Err<Status>(BadArgument("Session config must be a JSON object"));
  }

  // Extract app name for tracking
  std::string app_name = ExtractAppNameFromConfig(config);
  if (app_name.empty()) {
    return Err<Status>(BadArgument("Unable to extract app name from config"));
  }

  // Check for existing session with same target
  if (config.contains("pid")) {
    pid_t target_pid = config["pid"];
    if (GetSession(target_pid) != nullptr) {
      return Err<Status>(InvalidOperation("Session already exists for PID " +
                                          std::to_string(target_pid)));
    }
  } else if (config.contains("app")) {
    // Check if app is already being instrumented
    auto existing_proc = utils::FindProcessByName(app_name);
    if (existing_proc.has_value() &&
        GetSession(existing_proc->pid) != nullptr) {
      return Err<Status>(
          InvalidOperation("Session already exists for app " + app_name));
    }
  }

  // Create the session
  Status status = CreateSingleSession(config);
  if (!status.Ok()) {
    LOGE("Failed to create session: {}", status.Message());
    return Err<Status>(status);
  }

  // Get the newly created session (should be the last one added)
  Session *session = m_sessions.Back().second.get();
  if (session == nullptr) {
    return Err<Status>(
        SdkFailure("Session creation succeeded but session is null"));
  }

  pid_t session_pid = session->GetPid();

  // Create and store session metadata
  SessionMetadata metadata(session_pid, app_name, config);
  m_session_metadata.Emplace(session_pid, std::move(metadata));

  // Update statistics
  m_total_sessions_created++;

  LOGI("Session created successfully for PID: {}", session_pid);

  // Return session information
  nlohmann::json session_data = {
      {"session_id", std::to_string(session_pid)},
      {"pid", session_pid},
      {"app", app_name},
      {"status", "active"},
      {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count()},
      {"config", config}};

  return Ok<nlohmann::json>(session_data);
}

Result<nlohmann::json, Status>
Device::CreateSessionWithCancellation(const nlohmann::json &config,
                                      std::function<bool()> should_cancel) {

  // Check for cancellation before starting
  if (should_cancel && should_cancel()) {
    return Err<Status>(Timeout("Session creation cancelled before starting"));
  }

  // Use the existing CreateSession implementation with periodic cancellation
  // checks For now, we'll leverage the existing CreateSession method. In a more
  // advanced implementation, we would add cancellation checks throughout the
  // session creation process.

  LOGI("Starting cancellable session creation with config: {}", config.dump());

  // Check cancellation one more time before the heavy operation
  if (should_cancel && should_cancel()) {
    return Err<Status>(Timeout("Session creation cancelled"));
  }

  // Delegate to the main CreateSession method
  // TODO: Enhance CreateSession to support cancellation checks internally
  auto result = CreateSession(config);

  // Check cancellation after creation
  if (should_cancel && should_cancel()) {
    // If we successfully created a session but now need to cancel,
    // we should clean it up
    if (result.IsOk()) {
      try {
        auto session_data = result.Unwrap();
        std::string session_id = session_data["session_id"];
        pid_t pid = std::stoi(session_id);
        RemoveSession(pid);
        LOGW("Cleaned up session {} after cancellation", session_id);
      } catch (const std::exception &e) {
        LOGE("Failed to clean up cancelled session: {}", e.what());
      }
    }
    return Err<Status>(Timeout("Session creation was cancelled"));
  }

  return result;
}

Status Device::RemoveSession(pid_t target_pid) {
  std::lock_guard<std::mutex> lock(m_sessions_mutex);

  LOGI("Removing session for PID: {}", target_pid);

  // Find the session
  Session *session = GetSession(target_pid);
  if (session == nullptr) {
    return NotFound("Session not found for PID " + std::to_string(target_pid));
  }

  // Find the process info for this session
  utils::ProcessInfo target_proc_info;
  bool found = false;

  m_sessions.ForEach([&target_pid, &target_proc_info,
                      &found](const utils::ProcessInfo &proc_info,
                              const std::unique_ptr<Session> &) {
    if (proc_info.pid == target_pid) {
      target_proc_info = proc_info;
      found = true;
    }
  });

  if (!found) {
    return NotFound("Process info not found for PID " +
                    std::to_string(target_pid));
  }

  // Update metadata status
  if (m_session_metadata.Contains(target_pid)) {
    m_session_metadata[target_pid].session_status = "terminated";
  }

  // Remove the session (this calls the Session destructor which cleans up)
  Status status = Detach(target_proc_info);
  if (!status.Ok()) {
    LOGW("Detach failed for PID {}: {}", target_pid, status.Message());
    // Continue with cleanup even if detach failed
  }

  // Clean up metadata
  m_session_metadata.Erase(target_pid);

  LOGI("Session removed successfully for PID: {}", target_pid);
  return Ok();
}

Result<nlohmann::json, Status>
Device::DrainSessionMessages(pid_t target_pid) {
  std::lock_guard<std::mutex> lock(m_sessions_mutex);

  Session *session = GetSession(target_pid);
  if (session == nullptr) {
    return Err<Status>(
        NotFound("Session not found for PID " + std::to_string(target_pid)));
  }

  size_t dropped_count = 0;
  auto messages = session->GetMessageCache().Drain(dropped_count);

  nlohmann::json messages_array = nlohmann::json::array();
  for (auto &msg : messages) {
    messages_array.push_back(std::move(msg));
  }

  nlohmann::json result = {
      {"session_id", std::to_string(target_pid)},
      {"pid", target_pid},
      {"message_count", messages_array.size()},
      {"dropped_count", dropped_count},
      {"messages", std::move(messages_array)}};

  return Ok<nlohmann::json>(result);
}

Result<nlohmann::json, Status> Device::GetSessionInfo(pid_t target_pid) const {
  std::lock_guard<std::mutex> lock(m_sessions_mutex);

  Session *session = GetSession(target_pid);
  if (session == nullptr) {
    return Err<Status>(
        NotFound("Session not found for PID " + std::to_string(target_pid)));
  }

  // Get metadata
  if (!m_session_metadata.Contains(target_pid)) {
    return Err<Status>(NotFound("Session metadata not found for PID " +
                                std::to_string(target_pid)));
  }

  const SessionMetadata &metadata = m_session_metadata.At(target_pid);
  nlohmann::json session_info = SessionToJson(session, metadata);

  return Ok<nlohmann::json>(session_info);
}

Result<nlohmann::json, Status>
Device::ListAllSessions(const nlohmann::json &filter) const {
  std::lock_guard<std::mutex> lock(m_sessions_mutex);

  LOGI("Listing sessions with filter: {}", filter.dump());

  nlohmann::json::array_t sessions_array;

  // Iterate through all sessions
  m_sessions.ForEach([this, &filter, &sessions_array](
                         const utils::ProcessInfo &proc_info,
                         const std::unique_ptr<Session> &session) {
    pid_t pid = session->GetPid();

    // Get metadata if available
    if (m_session_metadata.Contains(pid)) {
      const SessionMetadata &metadata = m_session_metadata.At(pid);

      // Apply filters if specified
      bool include = true;

      if (filter.contains("app") && !filter["app"].is_null()) {
        std::string filter_app = filter["app"];
        if (metadata.app_name != filter_app) {
          include = false;
        }
      }

      if (filter.contains("status") && !filter["status"].is_null()) {
        std::string filter_status = filter["status"];
        if (metadata.session_status != filter_status) {
          include = false;
        }
      }

      if (include) {
        sessions_array.push_back(SessionToJson(session.get(), metadata));
      }
    } else {
      // Session without metadata (legacy session)
      if (!filter.contains("app") && !filter.contains("status")) {
        nlohmann::json session_info = {
            {"session_id", std::to_string(pid)},
            {"pid", pid},
            {"app", proc_info.cmd_line},
            {"status", "active"},
            {"created_at", 0}, // Unknown creation time
            {"metadata_available", false}};
        sessions_array.push_back(session_info);
      }
    }
  });

  nlohmann::json result = {{"sessions", sessions_array},
                           {"total_count", sessions_array.size()}};

  return Ok<nlohmann::json>(result);
}

nlohmann::json Device::GetSessionStatistics() const {
  std::lock_guard<std::mutex> lock(m_sessions_mutex);

  auto uptime = std::chrono::steady_clock::now() - m_device_created_at;
  auto uptime_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(uptime).count();

  nlohmann::json stats = {
      {"active_sessions", m_sessions.GetSize()},
      {"total_sessions_created", m_total_sessions_created.load()},
      {"device_uptime_seconds", uptime_seconds},
      {"device_name", m_name},
      {"pending_spawns", m_pending_spawns.size()}};

  return stats;
}

// Helper methods

Status Device::CreateSingleSession(const nlohmann::json &session_config) {
  // Use the existing BuildOneSessionFromConfig logic but for a single session
  return BuildOneSessionFromConfig(session_config);
}

nlohmann::json Device::SessionToJson(const Session *session,
                                     const SessionMetadata &metadata) const {
  auto created_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                               metadata.created_at.time_since_epoch())
                               .count();

  nlohmann::json session_info = {{"session_id", std::to_string(metadata.pid)},
                                 {"pid", metadata.pid},
                                 {"app", metadata.app_name},
                                 {"status", metadata.session_status},
                                 {"created_at", created_timestamp},
                                 {"config", metadata.config}};

  // Add additional session details if available
  if (session != nullptr) {
    session_info["is_attaching"] = session->IsAttaching();
  }

  return session_info;
}

std::string
Device::ExtractAppNameFromConfig(const nlohmann::json &config) const {
  if (config.contains("app") && config["app"].is_string()) {
    return config["app"];
  }

  if (config.contains("pid") && config["pid"].is_number()) {
    pid_t pid = config["pid"];
    auto proc_info = utils::FindProcessByPid(pid);
    if (proc_info.has_value()) {
      return proc_info->cmd_line;
    }
  }

  if (config.contains("am_start") && config["am_start"].is_string()) {
    std::string am_command = config["am_start"];
    auto package_name = ExtractAppNameFromAmCommand(am_command);
    if (package_name.has_value()) {
      return std::string(*package_name);
    }
  }

  return "unknown";
}

} // namespace frida