//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Application.h"
#include "frida-core.h"
#include "frida/Device.h"
#include "nlohmann/json.hpp"
#include "utils/Log.h"
#include "utils/Status.h"
#include "utils/System.h"
#include <cstdlib>
using nlohmann::json;

constexpr std::string_view kSessionsKey = "sessions";

namespace {
void AndroidEnvCheck() {
#ifdef TARGET_ANDROID
  // Check if the application is running as root
  if (getuid() != 0) {
    LOG(FATAL) << "This application must be run as root, exiting";
    exit(EXIT_FAILURE);
  }
  // Turn SELinux to permissive mode
  frida_selinux_patch_policy();
#endif
}
} // namespace

class Application::Impl {
public:
  explicit Impl(std::string_view config);
  ~Impl();

  void Run() const;

private:
  struct LoopDeleter {
    void operator()(GMainLoop *loop) const noexcept { g_main_loop_unref(loop); }
  };
  std::unique_ptr<GMainLoop, LoopDeleter> mLoop;
  json mOriginalConfig;
  std::vector<utils::ProcessInfo> mProcessInfos;
  std::unique_ptr<frida::Device> mDevice;
};

Application::Impl::Impl(std::string_view config) {
  frida_init();
  AndroidEnvCheck();

  mLoop =
      std::unique_ptr<GMainLoop, LoopDeleter>(g_main_loop_new(nullptr, TRUE));
  mDevice = std::make_unique<frida::Device>();

  mOriginalConfig = json::parse(config);
  if (!mOriginalConfig.contains(kSessionsKey)) {
    LOG(FATAL) << "Configuration must contain 'sessions' key, exiting";
    exit(EXIT_FAILURE);
  }
  // Discard the top-level key and focus on 'sessions'
  mOriginalConfig = mOriginalConfig[kSessionsKey];
  if (!mOriginalConfig.is_array()) {
    LOG(FATAL) << "Configuration 'sessions' must be an array, exiting";
    exit(EXIT_FAILURE);
  }

  Status status = mDevice->BuildSessionsFromConfig(mOriginalConfig);

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

  mDevice->Resume();
  if (g_main_loop_is_running(mLoop.get()) != 0) {
    g_main_loop_run(mLoop.get());
  }

  LOG(INFO) << "Application main loop stopped running";
}

Application::Application(
    std::string_view config) // NOLINT(*-unnecessary-value-param)
    : mImpl(std::make_unique<Impl>(config)) {}

Application::~Application() { LOG(INFO) << "Destroying Application" << this; }

void Application::Run() const {
  LOG(INFO) << "Running Application " << this;
  mImpl->Run();
}
