//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Application.h"

// todo: move this header to frida/
#include "frida/FridaHelper.h"
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
  std::unique_ptr<GMainLoop, LoopDeleter> m_loop;
  json m_original_config;
  std::vector<utils::ProcessInfo> m_process_infos;
  std::unique_ptr<frida::Device> m_device;
};

Application::Impl::Impl(std::string_view config) {
  frida_init();
  AndroidEnvCheck();

  m_loop =
      std::unique_ptr<GMainLoop, LoopDeleter>(g_main_loop_new(nullptr, TRUE));
  m_device = std::make_unique<frida::Device>();

  m_original_config = json::parse(config);
  if (!m_original_config.contains(kSessionsKey)) {
    LOG(FATAL) << "Configuration must contain 'sessions' key, exiting";
    exit(EXIT_FAILURE);
  }
  // Discard the top-level key and focus on 'sessions'
  m_original_config = m_original_config[kSessionsKey];
  if (!m_original_config.is_array()) {
    LOG(FATAL) << "Configuration 'sessions' must be an array, exiting";
    exit(EXIT_FAILURE);
  }

  Status status = m_device->BuildSessionsFromConfig(m_original_config);

  if (!status.Ok()) {
    LOG(FATAL) << "Failed to attach processes: " << status.Message();
  }
}

Application::Impl::~Impl() {
  // Note: Deconstructing order matters here
  m_device.reset();
  m_loop.reset();
}

void Application::Impl::Run() const {
  CHECK(m_loop != nullptr);

  m_device->Resume();
  if (g_main_loop_is_running(m_loop.get()) != 0) {
    g_main_loop_run(m_loop.get());
  }

  LOG(INFO) << "Application main loop stopped running";
}

Application::Application(
    std::string_view config) // NOLINT(*-unnecessary-value-param)
    : m_impl(std::make_unique<Impl>(config)) {}

Application::~Application() { LOG(INFO) << "Destroying Application" << this; }

void Application::Run() const {
  LOG(INFO) << "Running Application " << this;
  m_impl->Run();
}
