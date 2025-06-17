//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Device.h"
#include "frida-core.h"
#include "utils/Log.h"
#include "utils/Status.h"
#include "utils/Subprocess.h"
#include "utils/Util.h"

namespace frida {
namespace {
constexpr std::string_view kAppNameKey = "app";
constexpr std::string_view kPidKey = "pid";

class DeviceSpawnGatingGuard {
public:
  explicit DeviceSpawnGatingGuard(FridaDevice *device) : mDevice(device) {
    CHECK(mDevice != nullptr);
    GError *error = nullptr;
    frida_device_enable_spawn_gating_sync(mDevice, nullptr, &error);
    if (error != nullptr) {
      LOG(ERROR) << "Failed to enable spawn gating: " << error->message;
    }
    mEnabled = (error == nullptr);
  }

  ~DeviceSpawnGatingGuard() {
    if (mEnabled) {
      GError *error = nullptr;
      frida_device_disable_spawn_gating_sync(mDevice, nullptr, &error);
      if (error != nullptr) {
        LOG(ERROR) << "Failed to disable spawn gating: " << error->message;
      }
    }
  }

  bool IsEnabled() const { return mEnabled; }

private:
  FridaDevice *mDevice = nullptr;
  bool mEnabled = false;
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
} // namespace

Device::Device() {
  LOG(INFO) << "Creating frida device " << this;

  mManager = frida_device_manager_new();
  CHECK(mManager != nullptr);

  GError *error = nullptr;
  auto *devices =
      frida_device_manager_enumerate_devices_sync(mManager, nullptr, &error);
  CHECK(error == nullptr);

  const auto n_devices = frida_device_list_size(devices);
  for (int i = 0; i < n_devices; ++i) {
    auto *device = frida_device_list_get(devices, i);
    LOG(DEBUG) << "Found device " << frida_device_get_name(device)
               << ", type: " << frida_device_get_dtype(device);

    if (frida_device_get_dtype(device) == FRIDA_DEVICE_TYPE_LOCAL) {
      mDevice = g_object_ref(device);
      mName = frida_device_get_name(device);
    }

    g_object_unref(device);
  }

  if (mDevice == nullptr) {
    LOG(ERROR) << "No valid device found, current device list:";
    for (int i = 0; i < n_devices; ++i) {
      auto *device = frida_device_list_get(devices, i);
      LOG(ERROR) << "Device " << frida_device_get_name(device);
    }
  }

  frida_unref(devices);
}

Device::~Device() {
  LOG(INFO) << "Destroying frida device " << mName << "@" << this;

  if (mDevice != nullptr) {
    frida_unref(mDevice);
    mDevice = nullptr;
  }
  if (mManager != nullptr) {
    frida_device_manager_close_sync(mManager, nullptr, nullptr);
    frida_unref(mManager);
    mManager = nullptr;
  }
}

Status Device::BuildSessionsFromConfig(const nlohmann::json &config) {
  CHECK(mDevice != nullptr);
  CHECK(config.is_array());
  mConfig = &config;

  for (const auto &session_config : config) {
    Status status = BuildOneSessionFromConfig(session_config);
    if (!status.Ok()) {
      return status;
    }
  }

  return Ok();
}

Status Device::Resume() {
  LOG(INFO) << "Resuming frida device " << mName << "@" << this;

  CHECK(mDevice != nullptr);

  for (const auto &pid : mPendingSpawns) {
    GError *error = nullptr;
    frida_device_resume_sync(mDevice, pid, nullptr, &error);
    if (error != nullptr) {
      LOG(ERROR) << "Error resuming frida device: " << error->message;
      g_error_free(error);
      return SdkFailure("frida resume api failed");
    }
  }

  mPendingSpawns.clear();
  return Ok();
}

Status Device::Attach(pid_t target_pid) {
  LOG(INFO) << "Attaching frida device " << mName << "@" << this
            << " targeting " << target_pid;

  CHECK(mDevice != nullptr);
  CHECK(!mSessions.Contains(target_pid));

  GError *error = nullptr;

  auto *session =
      frida_device_attach_sync(mDevice, target_pid, nullptr, nullptr, &error);
  if (error != nullptr) {
    LOG(ERROR) << "Error attaching frida device: " << error->message;
    frida_unref(session);

    return SdkFailure("frida attach api failed");
  }

  mSessions[target_pid] = std::make_unique<Session>(target_pid, session);

  return Ok();
}

// todo: is this resume-able?
Status Device::Detach(pid_t target_pid) {
  LOG(INFO) << "Detaching frida device " << mName << "@" << this;

  CHECK(mDevice != nullptr);
  CHECK(mSessions.Contains(target_pid));

  mSessions.Erase(target_pid);
  return Ok();
}

Status Device::SpawnAppAndAttach(std::string_view exec_name,
                                 const std::vector<std::string> &args) {
  LOG(INFO) << "Spawning and attaching to app " << exec_name;

  CHECK(mDevice != nullptr);

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
  auto spawn_pid = frida_device_spawn_sync(mDevice, exec_name.data(), options,
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

  mPendingSpawns.push_back(static_cast<pid_t>(spawn_pid));
  return Attach(static_cast<pid_t>(spawn_pid));
}

Status Device::LaunchAppAndAttach(std::string_view am_command_args) {
  // Assuming the am_command_args is space separated arguments
  LOG(INFO) << "Launching app with am command: " << am_command_args;

  CHECK(mDevice != nullptr);
  GError *error = nullptr;

  auto args = utils::SplitString(am_command_args, " ");
  if (args.empty()) {
    LOG(ERROR) << "No arguments provided for am command";
    return BadArgument("No arguments provided for am command");
  }

  utils::Subprocess am_process;
  DeviceSpawnGatingGuard guard(mDevice);
  CHECK(guard.IsEnabled());

  Status status = am_process.Spawn("sh", {"-c", std::string(am_command_args)});
  if (!status.Ok()) {
    LOG(ERROR) << "Failed to spawn am command: " << status.Message();
    return status;
  }

  auto result = am_process.Wait(10000);
  if (result.timedOut) {
    LOG(ERROR) << "AM command timed out";
    return InvalidOperation("AM command timed out");
  }
  if (result.exitStatus != 0) {
    LOG(ERROR) << "AM command failed with exit status: " << result.exitStatus
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
        frida_device_enumerate_pending_spawn_sync(mDevice, nullptr, &error);
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

        mPendingSpawns.push_back(static_cast<pid_t>(pid));
        return Attach(static_cast<pid_t>(pid));
      }

      frida_device_resume_sync(mDevice, pid, nullptr, &error);
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
  if (!mSessions.Contains(target_pid)) {
    return nullptr;
  }
  return mSessions.At(target_pid).get();
}

bool Device::EnumerateSessions(const EnumerateSessionCallback &callback) const {
  for (auto it = mSessions.CBegin(); it != mSessions.CEnd(); ++it) {
    const auto &session = it->second.get();
    if (callback(session)) {
      return true;
    }
  }
  return false;
}

Status Device::BuildOneSessionFromConfig(const nlohmann::json &session_config) {
  if (session_config.contains(kPidKey)) {
    int const pid = session_config[kPidKey].get<int>();
    CHECK(pid > 0);
    if (const auto proc = utils::FindProcessByPid(pid); proc.has_value()) {
      mProcessInfos.emplace_back(*proc);
    } else {
      return NotFound("Process not found");
    }
  } else if (session_config.contains(kAppNameKey)) {
    std::string const app_name = session_config[kAppNameKey].get<std::string>();
    CHECK(!app_name.empty());
    if (const auto proc = utils::FindProcessByName(app_name);
        proc.has_value()) {
      mProcessInfos.emplace_back(*proc);
    } else {
      return NotFound("Process not found");
    }
  } else {
    return BadArgument("No PID or app name provided");
  }

  if (mProcessInfos.empty() || mProcessInfos.back().Pid <= 0) {
    return BadArgument("Invalid PID");
  }
  pid_t pid = mProcessInfos.back().Pid;

  Status status = Attach(pid);
  if (!status.Ok()) {
    return status;
  }

  Session *session = GetSession(pid);
  CHECK(session != nullptr);

  CHECK_STATUS(session->LoadInlineScriptsFromConfig(session_config));
  CHECK_STATUS(session->LoadScriptFilesFromConfig(session_config));
  CHECK_STATUS(session->LoadPlugins(session_config));

  return Ok();
}

} // namespace frida