//
// Created by Hao, Zaijun on 2025/4/29.
//

#include "Session.h"
#include "utils/Log.h"

namespace frida {
Session::Session(pid_t pid, FridaSession *session)
    : mSession(session), mPid(pid) {
  LOG(INFO) << "Creating session " << this;
}

Session::~Session() {
  LOG(INFO) << "Destroying session " << this;
  if (LIKELY(IsAttaching())) {
    Detach();
  }
  if (LIKELY(mSession != nullptr)) {
    frida_unref(mSession);
  }
}

Status Session::CreateScript(std::string_view name, std::string_view source) {
  LOG(DEBUG) << "Creating script " << name << " for process " << mPid;

  if (mScripts.Contains(std::string(name))) {
    return InvalidOperation("Duplicate name");
  }
  mScripts[std::string(name)] =
      std::make_unique<Script>(name, source, mSession);

  return Ok();
}

bool Session::IsAttaching() const { return mAttaching; }

void Session::Resume() {
  if (mAttaching) {
    LOG(WARNING) << "Resuming a running session " << this;
    return;
  }
  GError *error = nullptr;
  frida_session_resume_sync(mSession, nullptr, &error);
  CHECK(error == nullptr);

  mAttaching = true;
}

void Session::Detach() {
  if (!mAttaching) {
    LOG(WARNING) << "Detaching an idle session " << this;
    return;
  }
  GError *error = nullptr;
  frida_session_detach_sync(mSession, nullptr, &error);
  CHECK(error == nullptr);
  mAttaching = false;
}

Status Session::LoadPlugins(const nlohmann::json &config) {
  mPlugins = plugin::MakePlugin(this, config);
  return Ok();
}

Script *Session::GetScript(std::string_view name) const {
  if (!mScripts.Contains(name)) {
    return nullptr;
  }
  return mScripts.At(name).get();
}

} // namespace frida