//
// Created by Hao, Zaijun on 2025/4/27.
//
#include "Application.h"
#include "frida/Device.h"
#include "frida/Script.h"
#include "utils/Log.h"
#include "utils/System.h"

class Application::Impl {
public:
  explicit Impl(TaskConfig config);
  ~Impl();

  void Run() const;

private:
  struct LoopDeleter {
    void operator()(GMainLoop *loop) const noexcept { g_main_loop_unref(loop); }
  };
  std::unique_ptr<GMainLoop, LoopDeleter> mLoop;
  TaskConfig mConfig;
  std::unique_ptr<frida::Device> mDevice;
};

Application::Impl::Impl(TaskConfig config) : mConfig(std::move(config)) {
  frida_init();

  mLoop = std::unique_ptr<GMainLoop, LoopDeleter>(g_main_loop_new(nullptr, TRUE));
  mDevice = std::make_unique<frida::Device>();

  // todo: support attaching to app by name
  Status status = mDevice->Attach(*mConfig.pid);
  CHECK(status.Ok());
  auto *session = mDevice->GetSession(*mConfig.pid);

  for (int i = 0; i < mConfig.scripts.size(); ++i) {
    auto script_name = "App-" + std::to_string(i);
    auto script_source = utils::ReadFileToBuffer(mConfig.scripts[i]);
    status = session->CreateScript(script_name, script_source);
    CHECK(status.Ok());

    auto *script = session->GetScript(script_name);
    script->Load();
  }
}

Application::Impl::~Impl() {
  // Deconstructing order matters here
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

Application::Application(TaskConfig config) // NOLINT(*-unnecessary-value-param)
    : mImpl(std::make_unique<Impl>(config)) {
  LOG(INFO) << "Creating Application " << this;
}

Application::~Application() { LOG(INFO) << "Destroying Application" << this; }

void Application::Run() const {
  LOG(INFO) << "Running Application " << this;
  mImpl->Run();
}
