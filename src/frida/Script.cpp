//
// Created by Hao, Zaijun on 2025/4/27.
//

#include "Script.h"
#include "utils/Log.h"

#include "nlohmann/json.hpp"
#include <cstdint>
#include <cstdio>
#include <mutex>
using nlohmann::json;

#include <ranges>

#define LOCK() const std::lock_guard<std::mutex> lock(m_mutex);

constexpr std::string_view kClientMessagePrefix = "[Client]";
constexpr std::string_view kRpcIdentifier = "frida:rpc";
constexpr std::string_view kRpcResultOk = "ok";
constexpr std::string_view kRpcResultError = "error";

#include "java_runtime.js.h"

static bool LoadJavaRuntimeIfNeeded(std::string_view source) {
  return source.find("Java.") != std::string_view::npos;
}

namespace frida {
Script::Script(std::string_view name, std::string_view source,
               FridaSession *session)
    : m_name(name), m_source(source), m_session(session) {
  LOGI("Creating script {}", (void *)this);
}

Script::~Script() {
  LOGI("Destroying script {}@{}", m_name, (void *)this);

  if (m_loaded) {
    Unload();
  }
}

void Script::Load() {
  LOGI("Loading script {}@{}", m_name, (void *)this);
  GError *error{nullptr};

  {
    FridaScriptOptions *options = frida_script_options_new();
    LOCK();
    CHECK(m_session != nullptr);

    if (!m_name.empty()) {
      frida_script_options_set_name(options, m_name.c_str());
    }
    frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS);

    char *source = const_cast<char *>(m_source.data());
    char *buffer = nullptr;
    if (LoadJavaRuntimeIfNeeded(m_source)) {
      LOGI("Loading Java runtime for script {}", m_name);

      size_t needed_size = kScriptSource.size() + m_source.size() + 5;
      buffer = new char[needed_size];
      snprintf(buffer, needed_size, "%s\n%s", kScriptSource.data(),
               m_source.data());
      source = buffer;
    }
    m_script = frida_session_create_script_sync(m_session, source, options,
                                                nullptr, &error);
    delete[] buffer;
    if (m_script == nullptr || error != nullptr) {
      LOGE("Failed to create script {}@{}", m_name, (void *)this);
      if (error != nullptr) {
        LOGE("error: {} -> {}", error->code, error->message);
      }
      exit(EXIT_FAILURE);
    }

    // todo: fix compile error here
    // g_clear_object(options);

    g_signal_connect(m_script, "message", G_CALLBACK(OnMessage), (void *)this);
    m_loaded = true;
  }

  frida_script_load_sync(m_script, nullptr, &error);
  CHECK(error == nullptr);

  LOGD("Script loaded {}@{}", m_name, (void *)this);
}

void Script::Unload() {
  LOGI("Unloading script {}@{}", m_name, (void *)this);

  GError *error{nullptr};
  LOCK();
  frida_script_unload_sync(m_script, nullptr, &error);
  CHECK(error != nullptr);

  frida_unref(m_script);
  m_script = nullptr;
  m_loaded = false;
}

void Script::AddMessageCallback(std::string_view name,
                                OnMessageCallback callback) {
  LOCK();
  m_callbacks.emplace(name, std::move(callback));
}

void Script::RemoveCallback(std::string_view name) {
  LOCK();
  if (const auto iter = m_callbacks.find(std::string(name));
      iter != m_callbacks.end()) {
    m_callbacks.erase(iter);
  }
}

RpcResult Script::RpcCallSync(std::string_view method,
                              std::string_view param_json) {
  CHECK(!method.empty());

  int const call_id = SendRpcCall(method, param_json);
  if (call_id < 0) {
    return std::unexpected(
        nlohmann::json{{"error", "Failed to send RPC call"}});
  }

  return WaitForRpcCallResult(call_id);
}

int Script::SendRpcCall(std::string_view method, std::string_view param_json) {
  CHECK(!method.empty());

  std::string message;
  message.reserve(256);

  int const call_id = m_rpc_call_id++;
  message.append("[\"")
      .append(kRpcIdentifier)
      .append("\",")
      .append(std::to_string(call_id))
      .append(R"(,"call",")")
      .append(method)
      .append("\",")
      .append(param_json.empty() ? "[]" : param_json)
      .append("]");

  frida_script_post(m_script, message.c_str(), nullptr);
  LOGD("Sent RPC call {} with ID {}", message, call_id);

  return call_id;
}

RpcResult Script::WaitForRpcCallResult(int call_id) {
  std::unique_lock<std::mutex> lock(m_rpc_call_mutex);
  m_rpc_call_cond_var.wait(
      lock, [this, call_id] { return m_rpc_call_results.Contains(call_id); });

  auto result = std::move(m_rpc_call_results[call_id]);
  m_rpc_call_results.Erase(call_id);

  return result;
}

void Script::OnMessage(const FridaScript *script, const gchar *message,
                       GBytes *data, gpointer user_data) {
  auto *s = static_cast<Script *>(user_data);
  CHECK(script != nullptr);

  s->ProcessMessage(script, std::string_view(message), data);
}

static void WriteLogMessage(json &msg) {
  auto const &level = msg["level"].get_ref<std::string &>();
  auto const &message = msg["payload"].get_ref<std::string &>();
  switch (EXPECT(level[0], 'i')) {
  case 'i':
    LOGI("{}{}", kClientMessagePrefix, message);
    return;
  case 'd':
    LOGD("{}{}", kClientMessagePrefix, message);
    return;
  case 'w':
    LOGW("{}{}", kClientMessagePrefix, message);
    return;
  case 'e':
    LOGE("{}{}", kClientMessagePrefix, message);
    return;
  default:
    LOGI("Unknown level {} [0]={}", level, level[0]);
  }
}

bool Script::MaybeProcessSystemMessage(nlohmann::json &msg) {
  if (!msg.is_object()) {
    return false;
  }
  if (!msg.contains("type")) {
    return false;
  }

  const auto &type = msg["type"];
  if (type == "log") {
    WriteLogMessage(msg);
    return true;
  }
  if (type == "send") {
    if (msg.contains("payload")) {
      const auto &payload = msg["payload"];
      if (payload.is_array() && payload.size() >= 3) {
        const std::string &identifier = payload[0].get<std::string>();
        if (identifier == kRpcIdentifier) {
          OnRpcReturn(msg);
          return true;
        }
      }
    } else {
      LOGW("Received send message without payload: {}", msg.dump());
      return false;
    }
  }

  return false;
}

void Script::OnRpcReturn(json &msg) {
  auto const &payload = msg["payload"];
  if (!payload.is_array() || payload.size() < 3) {
    LOGE("Invalid RPC return message: {}", msg.dump());
    return;
  }

  const std::string &identifier = payload[0].get<std::string>();
  if (identifier != kRpcIdentifier) {
    LOGE("Invalid RPC return identifier: {}", identifier);
    return;
  }
  int call_id = payload[1].get<int>();
  const std::string &type = payload[2].get<std::string>();

  if (type == kRpcResultOk) {
    if (payload.size() < 4) {
      LOGE("Invalid RPC return message: {}", msg.dump());
      return;
    }
    json result = payload[3];

    std::lock_guard lock(m_rpc_call_mutex);
    CHECK(!m_rpc_call_results.Contains(call_id));
    m_rpc_call_results[call_id] = std::move(result);

    m_rpc_call_cond_var.notify_all();
  } else if (type == kRpcResultError) {
    if (payload.size() < 4) {
      LOGE("Invalid RPC error message: {}", msg.dump());
      return;
    }
    json error = payload[3];

    std::lock_guard lock(m_rpc_call_mutex);
    CHECK(!m_rpc_call_results.Contains(call_id));
    m_rpc_call_results[call_id] = std::unexpected(std::move(error));

    m_rpc_call_cond_var.notify_all();
  } else {
    LOGE("Unknown RPC return type: {}", type);
  }
}

void Script::ProcessMessage(const FridaScript *script, std::string_view message,
                            GBytes *data) {
  CHECK(script == m_script);

  LOGD("Processing message: {}", message);
  auto msg_obj = json::parse(message);
  if (MaybeProcessSystemMessage(msg_obj)) {
    return;
  }

  gsize size = 0;

  const uint8_t *data_pointer = nullptr;
  size_t data_size = 0;

  if (UNLIKELY(data != nullptr)) {
    if (const auto *pointer = g_bytes_get_data(data, &size);
        pointer != nullptr && size > 0) {
      data_pointer = reinterpret_cast<const uint8_t *>(pointer);
      data_size = size;
    }
  }

  LOCK();
  for (const auto &callback : m_callbacks | std::views::values) {
    callback(this, message, data_pointer, data_size);
  }
}
} // namespace frida