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
    : m_session(session), m_pid(pid) {
  LOGI("Creating session {}", (void *)this);
}

Session::~Session() {
  LOGI("Destroying session {}", (void *)this);
  if (LIKELY(IsAttaching())) {
    Detach();
  }
  if (LIKELY(m_session != nullptr)) {
    frida_unref(m_session);
  }
}

Status Session::CreateScript(std::string_view name, std::string_view source) {
  LOGD("Creating script {} for process {}", name, m_pid);

  if (m_scripts.Contains(std::string(name))) {
    return InvalidOperation("Duplicate name");
  }
  m_scripts[std::string(name)] =
      std::make_unique<Script>(name, source, m_session);

  return Ok();
}

bool Session::IsAttaching() const { return m_attaching; }

void Session::Resume() {
  if (m_attaching) {
    LOGW("Resuming a running session {}", (void *)this);
    return;
  }
  GError *error = nullptr;
  frida_session_resume_sync(m_session, nullptr, &error);
  CHECK(error == nullptr);

  m_attaching = true;
}

void Session::Detach() {
  if (!m_attaching) {
    LOGW("Detaching an idle session {}", (void *)this);
    return;
  }
  GError *error = nullptr;
  frida_session_detach_sync(m_session, nullptr, &error);
  CHECK(error == nullptr);
  m_attaching = false;
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
  LOGI("Loaded user scripts");
  return Ok();
}

Status Session::LoadScriptFilesFromConfig(const nlohmann::json &config) {
  if (!config.contains(kScriptFilesKey)) {
    LOGD("No script files to load");
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
  LOGI("Loaded user scripts from files");
  return Ok();
}

Status Session::LoadPlugins(const nlohmann::json &config) {
  m_plugins = plugin::MakePlugin(this, config);
  return Ok();
}

Script *Session::GetScript(std::string_view name) const {
  if (!m_scripts.Contains(name)) {
    return nullptr;
  }
  return m_scripts.At(name).get();
}

Status Session::RemoveScript(std::string_view name) {
  if (!m_scripts.Contains(name)) {
    return NotFound("Script not found");
  }
  auto script = std::move(m_scripts.At(name));
  m_scripts.Erase(name);
  script->Unload();
  return Ok();
}

} // namespace frida