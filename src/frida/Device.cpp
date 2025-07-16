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
      LOG(ERROR) << "Failed to enable spawn gating: " << error->message;
    }
    m_enabled = (error == nullptr);
  }

  ~DeviceSpawnGatingGuard() {
    if (m_enabled) {
      GError *error = nullptr;
      frida_device_disable_spawn_gating_sync(m_device, nullptr, &error);
      if (error != nullptr) {
        LOG(ERROR) << "Failed to disable spawn gating: " << error->message;
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

  LOG(INFO) << "App " << app_name
            << " is running, attempting to kill it with PID: "
            << proc_info->pid;

  int ret = kill(proc_info->pid, SIGTERM);
  if (ret != 0) {
    LOG(ERROR) << "Failed to kill app " << app_name
               << " with PID: " << proc_info->pid
               << ", error: " << strerror(errno);
  } else {
    LOG(INFO) << "Successfully killed app " << app_name
              << " with PID: " << proc_info->pid;
  }
}
} // namespace

Device::Device() {
  LOG(INFO) << "Creating frida device " << this;

  m_manager = frida_device_manager_new();
  CHECK(m_manager != nullptr);

  GError *error = nullptr;
  auto *devices =
      frida_device_manager_enumerate_devices_sync(m_manager, nullptr, &error);
  CHECK(error == nullptr);

  const auto n_devices = frida_device_list_size(devices);
  for (int i = 0; i < n_devices; ++i) {
    auto *device = frida_device_list_get(devices, i);
    LOG(DEBUG) << "Found device " << frida_device_get_name(device)
               << ", type: " << frida_device_get_dtype(device);

    if (frida_device_get_dtype(device) == FRIDA_DEVICE_TYPE_LOCAL) {
      m_device = g_object_ref(device);
      m_name = frida_device_get_name(device);
    }

    g_object_unref(device);
  }

  if (m_device == nullptr) {
    LOG(ERROR) << "No valid device found, current device list:";
    for (int i = 0; i < n_devices; ++i) {
      auto *device = frida_device_list_get(devices, i);
      LOG(ERROR) << "Device " << frida_device_get_name(device);
    }
  }

  frida_unref(devices);
}

Device::~Device() {
  LOG(INFO) << "Destroying frida device " << m_name << "@" << this;

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
  LOG(INFO) << "Resuming frida device " << m_name << "@" << this;

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
  LOG(INFO) << "Attaching frida device " << m_name << "@" << this
            << " targeting " << proc_info.cmd_line;

  CHECK(m_device != nullptr);
  if (m_sessions.Contains(proc_info) && m_sessions.At(proc_info) != nullptr) {
    LOG(INFO) << "Already attached to process " << proc_info.cmd_line << "("
              << proc_info.pid << ")";
    return InvalidOperation("Multiple attachments");
  }

  GError *error = nullptr;

  auto *session = frida_device_attach_sync(m_device, proc_info.pid, nullptr,
                                           nullptr, &error);
  if (error != nullptr) {
    LOG(ERROR) << "Error attaching frida device: " << error->message;
    frida_unref(session);

    return SdkFailure("frida attach api failed");
  }

  m_sessions[proc_info] = std::make_unique<Session>(proc_info.pid, session);

  return Ok();
}

// todo: is this resume-able?
Status Device::Detach(const utils::ProcessInfo &proc_info) {
  LOG(INFO) << "Detaching frida device " << m_name << "@" << this
            << " targeting " << proc_info.cmd_line << "(" << proc_info.pid
            << ")";

  CHECK(m_device != nullptr);
  CHECK(m_sessions.Contains(proc_info));

  m_sessions.Erase(proc_info);
  return Ok();
}

Status Device::SpawnAppAndAttach(std::string_view exec_name,
                                 const std::vector<std::string> &args) {
  LOG(INFO) << "Spawning and attaching to app " << exec_name;

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

  LOG(INFO) << "Spawned app with PID: " << spawn_pid;
  if (error != nullptr) {
    LOG(ERROR) << "Error spawning app: " << error->message;
    g_error_free(error);
    return SdkFailure("frida spawn api failed");
  }
  if (spawn_pid <= 0) {
    LOG(ERROR) << "Invalid PID returned from frida spawn: " << spawn_pid;
    return SdkFailure("frida spawn returned invalid PID");
  }

  m_pending_spawns.push_back(static_cast<pid_t>(spawn_pid));
  auto proc_info = utils::FindProcessByPid(static_cast<pid_t>(spawn_pid));
  if (!proc_info.has_value()) {
    LOG(ERROR) << "Failed to find process by PID: " << spawn_pid;
    return NotFound("Process not found by PID");
  }
  return Attach(*proc_info);
}

Status Device::LaunchAppAndAttach(std::string_view am_command_args) {
  // Assuming the am_command_args is space separated arguments
  LOG(INFO) << "Launching app with am command: " << am_command_args;

  CHECK(m_device != nullptr);
  GError *error = nullptr;

  auto args = utils::SplitString(am_command_args, " ");
  if (args.empty()) {
    LOG(ERROR) << "No arguments provided for am command";
    return BadArgument("No arguments provided for am command");
  }

  utils::Subprocess am_process;
  DeviceSpawnGatingGuard guard(m_device);
  CHECK(guard.IsEnabled());

  Status status = am_process.Spawn("sh", {"-c", std::string(am_command_args)});
  if (!status.Ok()) {
    LOG(ERROR) << "Failed to spawn am command: " << status.Message();
    return status;
  }

  auto result = am_process.Wait(10000);
  if (result.timed_out) {
    LOG(ERROR) << "AM command timed out";
    return InvalidOperation("AM command timed out");
  }
  if (result.exit_status != 0) {
    LOG(ERROR) << "AM command failed with exit status: " << result.exit_status
               << ", stderr: " << result.stderr;
    return SdkFailure("AM command failed: " + result.stderr);
  }

  constexpr int64_t kWaitForAppLaunchTimeoutMs = 10000;
  auto package_name = ExtractAppNameFromAmCommand(am_command_args);
  if (!package_name.has_value()) {
    LOG(ERROR) << "Failed to extract package name from AM command: "
               << am_command_args;
    return BadArgument("Failed to extract package name from AM command");
  }
  LOG(INFO) << "Extracted package name: " << *package_name;

  int64_t start_time = GetNowMs();
  while (true) {
    FridaSpawnList *spawned_apps =
        frida_device_enumerate_pending_spawn_sync(m_device, nullptr, &error);
    if (error != nullptr) {
      LOG(ERROR) << "Error enumerating pending spawns: " << error->message;
      return SdkFailure("frida enumerate pending spawn failed");
    }

    bool found = false;
    for (int i = 0; i < frida_spawn_list_size(spawned_apps); ++i) {
      auto *spawn = frida_spawn_list_get(spawned_apps, i);
      auto const *identifier = frida_spawn_get_identifier(spawn);
      auto pid = frida_spawn_get_pid(spawn);

      LOG(DEBUG) << "Found pending spawn: " << identifier << "(PID: " << pid
                 << ")";
      if (identifier == *package_name) {
        found = true;
        LOG(INFO) << "Found pending spawn with PID: " << pid;
        frida_unref(spawned_apps);
        frida_unref(spawn);

        m_pending_spawns.push_back(static_cast<pid_t>(pid));
        auto proc_info = utils::FindProcessByPid(static_cast<pid_t>(pid));
        if (!proc_info.has_value()) {
          LOG(ERROR) << "Failed to find process by PID: " << pid;
          return NotFound("Process not found by PID");
        }
        return Attach(*proc_info);
      }

      frida_device_resume_sync(m_device, pid, nullptr, &error);
      if (error != nullptr) {
        LOG(ERROR) << "Error resuming spawn with PID " << pid << ": "
                   << error->message;
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
  LOG(INFO) << "AM command executed successfully, stdout: " << result.stdout;
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
    LOG(ERROR) << "Failed to attach to app from config: " << status.Message();
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

} // namespace frida