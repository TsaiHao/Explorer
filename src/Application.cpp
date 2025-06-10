//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Application.h"
#include "frida-core.h"
#include "frida/Device.h"
#include "frida/Script.h"
#include "nlohmann/json.hpp"
#include "utils/Log.h"
#include "utils/Status.h"
#include "utils/System.h"
#include <string>
using nlohmann::json;

constexpr std::string_view kAppNameKey = "app";
constexpr std::string_view kPidKey = "pid";
constexpr std::string_view kScriptFilesKey = "scripts";
constexpr std::string_view kScriptsKey = "script_source";
constexpr std::string_view kTracerKey = "trace";

static void DisableSELinuxIfNeeded() {
#ifdef TARGET_ANDROID
  // Turn SELinux to permissive mode
  frida_selinux_patch_policy();
#endif
}

// todo: move to frida::Session class
static Status LoadUserScriptsFromConfig(frida::Session *session,
                                        const json &config) {
  if (!config.contains(kScriptsKey)) {
    return Ok();
  }
  auto const &scripts = config[kScriptsKey];

  if (scripts.is_string()) {
    auto const &script = scripts.get_ref<const std::string &>();
    if (script.empty()) {
      return BadArgument("Empty script");
    }
    CHECK_STATUS(session->CreateScript("inline_script", script));

    auto *user_script = session->GetScript("inline_script");
    if (user_script == nullptr) {
      return NotFound("Script not found");
    }
    user_script->Load();
  } else if (scripts.is_array()) {
    for (int i = 0; i < scripts.size(); ++i) {
      auto const &script = scripts[i];
      if (!script.is_string()) {
        return BadArgument("Invalid script format");
      }
      auto const &script_str = script.get_ref<const std::string &>();
      if (script_str.empty()) {
        return BadArgument("Empty script");
      }

      auto const &script_name = "inline_script_" + std::to_string(i);
      session->CreateScript(script_name, script_str);
      auto *user_script = session->GetScript(script_name);
      if (user_script == nullptr) {
        return NotFound("Script not found");
      }
      user_script->Load();
    }
  } else {
    return BadArgument("Invalid scripts format");
  }
  LOG(INFO) << "Loaded user scripts";
  return Ok();
}

static Status LoadFunctionTracerFromConfig(frida::Session *session,
                                                       const json &config) {
  return session->LoadPlugins(config);
}


static Status LoadUserScriptFilsFromConfig(frida::Session *session,
                                           const json &config) {
  if (!config.contains(kScriptFilesKey)) {
    LOG(DEBUG) << "No script files to load";
    return Ok();
  }
  auto const &script_files = config[kScriptFilesKey];

  if (script_files.is_string()) {
    auto const &script_file = script_files.get_ref<const std::string &>();
    if (script_file.empty()) {
      return BadArgument("Empty script file");
    }
    CHECK_STATUS(session->CreateScript(script_file,
                                       utils::ReadFileToBuffer(script_file)));

    auto *user_script = session->GetScript(script_file);
    if (user_script == nullptr) {
      return NotFound("Script not found");
    }
    user_script->Load();
  } else if (script_files.is_array()) {
    for (auto const &script_file : script_files) {
      if (!script_file.is_string()) {
        return BadArgument("Invalid script file format");
      }
      auto const &script_file_str = script_file.get_ref<const std::string &>();
      if (script_file_str.empty()) {
        return BadArgument("Empty script file");
      }

      session->CreateScript(script_file_str,
                            utils::ReadFileToBuffer(script_file_str));
      auto *user_script = session->GetScript(script_file_str);
      if (user_script == nullptr) {
        return NotFound("Script not found");
      }
      user_script->Load();
    }
  } else {
    return BadArgument("Invalid scripts format");
  }
  LOG(INFO) << "Loaded user scripts from files";
  return Ok();
}

class Application::Impl {
public:
  explicit Impl(std::string_view config);
  ~Impl();

  void Run() const;

private:
  Status BuildSessionFromConfig(const json &session_config);
  Status AttachProcessFromConfig(const json &config);

  struct LoopDeleter {
    void operator()(GMainLoop *loop) const noexcept { g_main_loop_unref(loop); }
  };
  std::unique_ptr<GMainLoop, LoopDeleter> mLoop;
  json mOriginalConfig;
  std::vector<utils::ProcessInfo> mProcessInfos;
  std::unique_ptr<frida::Device> mDevice;
};

static void PrintAllProcessesOnExit() {
  LOG(INFO) << "Listing all processes for debugging";
  utils::EnumerateProcesses([](const utils::ProcessInfo &info) {
    LOG(INFO) << "Process: " << info.Command << " (PID: " << info.Pid << ") - "
              << info.CmdLine;
    return false;
  });
}

Application::Impl::Impl(std::string_view config)
    : mOriginalConfig(json::parse(config)) {
  frida_init();
  DisableSELinuxIfNeeded();

  mLoop =
      std::unique_ptr<GMainLoop, LoopDeleter>(g_main_loop_new(nullptr, TRUE));
  mDevice = std::make_unique<frida::Device>();

  Status status;
  if (mOriginalConfig.is_object()) {
    status = BuildSessionFromConfig(mOriginalConfig);
  } else if (mOriginalConfig.is_array()) {
    for (auto const &session_config : mOriginalConfig) {
      status = BuildSessionFromConfig(session_config);
      if (!status.Ok()) {
        break;
      }
    }
  }

  if (!status.Ok()) {
    LOG(FATAL) << "Failed to attach processes: " << status.Message();
  }
}

Application::Impl::~Impl() {
  // Note: Deconstructing order matters here
  mDevice.reset();
  mLoop.reset();
}

void Application::Impl::Run() const {
  CHECK(mLoop != nullptr);

  if (g_main_loop_is_running(mLoop.get()) != 0) {
    g_main_loop_run(mLoop.get());
  }

  LOG(INFO) << "Application main loop stopped running";
}

Status Application::Impl::AttachProcessFromConfig(const json &config) {
  if (config.contains(kPidKey)) {
    int const pid = config[kPidKey].get<int>();
    CHECK(pid > 0);
    if (const auto proc = utils::FindProcessByPid(pid); proc.has_value()) {
      mProcessInfos.emplace_back(*proc);
    } else {
      return NotFound("Process not found");
    }
  } else if (config.contains(kAppNameKey)) {
    std::string const app_name = config[kAppNameKey].get<std::string>();
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

  return mDevice->Attach(mProcessInfos.back().Pid);
}

Status Application::Impl::BuildSessionFromConfig(const json &session_config) {
  CHECK_STATUS(AttachProcessFromConfig(session_config));

  const pid_t pid = mProcessInfos.back().Pid;
  auto *session = mDevice->GetSession(pid);

  CHECK(session != nullptr);
  CHECK_STATUS(LoadUserScriptsFromConfig(session, session_config));
  CHECK_STATUS(LoadUserScriptFilsFromConfig(session, session_config));
  CHECK_STATUS(LoadFunctionTracerFromConfig(session, session_config));

  return Ok();
}

Application::Application(
    std::string_view config) // NOLINT(*-unnecessary-value-param)
    : mImpl(std::make_unique<Impl>(config)) {
  LOG(INFO) << "Creating Application " << this;
}

Application::~Application() { LOG(INFO) << "Destroying Application" << this; }

void Application::Run() const {
  LOG(INFO) << "Running Application " << this;
  mImpl->Run();
}
