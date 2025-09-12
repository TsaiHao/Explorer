//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Application.h"
// todo: move this header to frida/
#include "frida/Device.h"
#include "nlohmann/json.hpp"
#include "utils/Log.h"
#include "utils/Status.h"
#include "utils/System.h"
#include "version.h"

#include "spdlog/sinks/android_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <iostream>
#include <cstdlib>
#include <string>
using nlohmann::json;

constexpr std::string_view kSessionsKey = "sessions";
constexpr std::string_view kConfigFilePathAbsolute =
    "/data/local/tmp/config.json";

namespace {
void AndroidEnvCheck() {
#ifdef TARGET_ANDROID
  // Check if the application is running as root
  if (getuid() != 0) {
    LOGE("This application must be run as root, exiting");
    exit(EXIT_FAILURE);
  }
  // Turn SELinux to permissive mode
  frida_selinux_patch_policy();
#endif
}

void InitLogger() {
    std::vector<spdlog::sink_ptr> sinks;
    
    auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    sinks.push_back(stdout_sink);
    
    auto android_sink = std::make_shared<spdlog::sinks::android_sink_mt>("Explorer", true);
    sinks.push_back(android_sink);
    
    std::string format_pattern = "[%Y-%m-%d %H:%M:%S.%e] [%P:%t] [%l] %v";
    
    for (auto& sink : sinks) {
        sink->set_pattern(format_pattern);
    }
    
    auto logger = std::make_shared<spdlog::logger>("default", sinks.begin(), sinks.end());
    
#ifdef EXP_DEBUG
    logger->set_level(spdlog::level::trace);
#else
    logger->set_level(spdlog::level::info);
#endif

    logger->flush_on(spdlog::level::info);
    
    spdlog::set_default_logger(logger);
    spdlog::flush_every(std::chrono::seconds(1));
}
} // namespace

class Application::Impl {
public:
  explicit Impl(const std::vector<std::string_view>& args);
  ~Impl();

  void Run() const;

private:
  void HandleArgs(const std::vector<std::string_view>& args);

  struct LoopDeleter {
    void operator()(GMainLoop *loop) const noexcept { g_main_loop_unref(loop); }
  };
  std::unique_ptr<GMainLoop, LoopDeleter> m_loop;
  json m_original_config;
  std::vector<utils::ProcessInfo> m_process_infos;

  std::unique_ptr<frida::Device> m_device;
};

Application::Impl::Impl(const std::vector<std::string_view>& args) {
  InitLogger();

  frida_init();
  AndroidEnvCheck();

  HandleArgs(args);

  std::string config;

  if (utils::FileExists(kConfigFilePathAbsolute)) {
    config = utils::ReadFileToBuffer(kConfigFilePathAbsolute);
  } else {
    LOGE("Config file not found in location: {}", kConfigFilePathAbsolute);
    exit(1);
  }

  m_loop =
      std::unique_ptr<GMainLoop, LoopDeleter>(g_main_loop_new(nullptr, TRUE));
  m_device = std::make_unique<frida::Device>();

  m_original_config = json::parse(config);
  if (!m_original_config.contains(kSessionsKey)) {
    LOGE("Configuration must contain a 'sessions' key, exiting");
    exit(EXIT_FAILURE);
  }
  // Discard the top-level key and focus on 'sessions'
  m_original_config = m_original_config[kSessionsKey];
  if (!m_original_config.is_array()) {
    LOGE("Configuration 'sessions' must be an array, exiting");
    exit(EXIT_FAILURE);
  }

  Status status = m_device->BuildSessionsFromConfig(m_original_config);

  if (!status.Ok()) {
    LOGE("Failed to attach processes: {}", status.Message());
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

  LOGI("Application main loop stopped running");
}

void Application::Impl::HandleArgs(const std::vector<std::string_view>& args) {
  constexpr std::string_view kHelpOption = "-help";
  constexpr std::string_view kVersionOption = "-version";

  for (int i = 1; i < static_cast<int>(args.size()); ++i) {
    const auto &arg = args[i];

    if (arg == kHelpOption) {
      std::cout << "Usage: explorer [options]\n"
                   "Options:\n"
                   "  --help       Show this help message\n"
                   "  --version    Show version information\n";
      exit(0);
    } else if (arg == kVersionOption) {
      std::cout << "Explorer version " << VERSION_STRING << "\n";
      exit(0);
    } else {
      std::cerr << "Unknown argument: " << arg << "\n";
      exit(1);
    }
  }
}

Application::Application(
    const std::vector<std::string_view>& args)
    : m_impl(std::make_unique<Impl>(args)) {}

Application::~Application() { LOGI("Destroying Application {}", (void *)this); }

void Application::Run() const {
  LOGI("Running Application {}", (void *)this);
  m_impl->Run();
}
