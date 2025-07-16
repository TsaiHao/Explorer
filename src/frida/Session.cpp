//
// Created by Hao, Zaijun on 2025/4/29.
//

#include "Session.h"
#include "utils/Log.h"
#include "utils/Status.h"
#include "utils/System.h"

namespace frida {
namespace {
constexpr std::string_view kScriptFilesKey = "scripts";
constexpr std::string_view kScriptsKey = "script_source";
} // namespace
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

Status Session::LoadInlineScriptsFromConfig(const nlohmann::json &config) {
  if (!config.contains(kScriptsKey)) {
    return Ok();
  }
  auto const &scripts = config[kScriptsKey];

  if (scripts.is_string()) {
    auto const &script = scripts.get_ref<const std::string &>();
    if (script.empty()) {
      return BadArgument("Empty script");
    }
    CHECK_STATUS(CreateScript("inline_script", script));

    auto *user_script = GetScript("inline_script");
    if (user_script == nullptr) {
      return NotFound("Script not found");
    }
    user_script->Load();
  } else if (scripts.is_array()) {
    for (size_t i = 0; i < scripts.size(); ++i) {
      auto const &script = scripts[i];
      if (!script.is_string()) {
        return BadArgument("Invalid script format");
      }
      auto const &script_str = script.get_ref<const std::string &>();
      if (script_str.empty()) {
        return BadArgument("Empty script");
      }

      auto const &script_name = "inline_script_" + std::to_string(i);
      CreateScript(script_name, script_str);
      auto *user_script = GetScript(script_name);
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
Status Session::LoadScriptFilesFromConfig(const nlohmann::json &config) {
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
    CHECK_STATUS(
        CreateScript(script_file, utils::ReadFileToBuffer(script_file)));

    auto *user_script = GetScript(script_file);
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

      CreateScript(script_file_str, utils::ReadFileToBuffer(script_file_str));
      auto *user_script = GetScript(script_file_str);
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

Status Session::RemoveScript(std::string_view name) {
  if (!mScripts.Contains(name)) {
    return NotFound("Script not found");
  }
  auto script = std::move(mScripts.At(name));
  mScripts.Erase(name);
  script->Unload();
  return Ok();
}

} // namespace frida