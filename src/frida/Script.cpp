//
// Created by Hao, Zaijun on 2025/4/27.
//

#include "Script.h"
#include "utils/Log.h"

#include "nlohmann/json.hpp"
#include <mutex>
using nlohmann::json;

#include <ranges>

#define LOCK() const std::lock_guard<std::mutex> lock(mMutex);

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
    : mName(name), mSource(source), mSession(session) {
  LOG(INFO) << "Creating script " << this;
}

Script::~Script() {
  LOG(INFO) << "Destroying script " << mName << "@" << this;

  if (mLoaded) {
    Unload();
  }
}

void Script::Load() {
  LOG(INFO) << "Loading script " << mName << "@" << this;
  GError *error{nullptr};

  {
    FridaScriptOptions *options = frida_script_options_new();
    LOCK();
    CHECK(mSession != nullptr);

    if (!mName.empty()) {
      frida_script_options_set_name(options, mName.c_str());
    }
    frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS);

    char *source = const_cast<char *>(mSource.data());
    char *buffer = nullptr;
    if (LoadJavaRuntimeIfNeeded(mSource)) {
      LOG(INFO) << "Loading Java runtime for script " << mName;

      size_t needed_size = kScriptSource.size() + mSource.size() + 5;
      buffer = new char[needed_size];
      snprintf(buffer, needed_size, "%s\n%s", kScriptSource.data(),
               mSource.data());
      source = buffer;
    }
    mScript = frida_session_create_script_sync(mSession, source, options,
                                               nullptr, &error);
    delete[] buffer;
    if (mScript == nullptr || error != nullptr) {
      LOG(ERROR) << "Failed to create script " << mName << "@" << this;
      if (error != nullptr) {
        LOG(ERROR) << "error: " << error->code << " -> " << error->message;
      }
      exit(EXIT_FAILURE);
    }

    // todo: fix compile error here
    // g_clear_object(options);

    g_signal_connect(mScript, "message", G_CALLBACK(OnMessage), this);
    mLoaded = true;
  }

  frida_script_load_sync(mScript, nullptr, &error);
  CHECK(error == nullptr);

  LOG(DEBUG) << "Script loaded " << mName << "@" << this;
}

void Script::Unload() {
  LOG(INFO) << "Unloading script " << mName << "@" << this;

  GError *error{nullptr};
  LOCK();
  frida_script_unload_sync(mScript, nullptr, &error);
  CHECK(error != nullptr);

  frida_unref(mScript);
  mScript = nullptr;
  mLoaded = false;
}

void Script::AddMessageCallback(std::string_view name,
                                OnMessageCallback callback) {
  LOCK();
  mCallbacks.emplace(name, std::move(callback));
}

void Script::RemoveCallback(std::string_view name) {
  LOCK();
  if (const auto iter = mCallbacks.find(std::string(name));
      iter != mCallbacks.end()) {
    mCallbacks.erase(iter);
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

  int const call_id = mRpcCallID++;
  message.append("[\"")
      .append(kRpcIdentifier)
      .append("\",")
      .append(std::to_string(call_id))
      .append(R"(,"call",")")
      .append(method)
      .append("\",")
      .append(param_json.empty() ? "[]" : param_json)
      .append("]");

  frida_script_post(mScript, message.c_str(), nullptr);
  LOG(DEBUG) << "Sent RPC call " << message << " with ID " << call_id;

  return call_id;
}

RpcResult Script::WaitForRpcCallResult(int call_id) {
  std::unique_lock<std::mutex> lock(mRpcCallMutex);
  mRpcCallCondVar.wait(
      lock, [this, call_id] { return mRpcCallResults.Contains(call_id); });

  auto result = std::move(mRpcCallResults[call_id]);
  mRpcCallResults.Erase(call_id);

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
    LOG(INFO) << kClientMessagePrefix << message;
    return;
  case 'd':
    LOG(DEBUG) << kClientMessagePrefix << message;
    return;
  case 'w':
    LOG(WARNING) << kClientMessagePrefix << message;
    return;
  case 'e':
    LOG(ERROR) << kClientMessagePrefix << message;
    return;
  default:
    LOG(INFO) << "Unknown level " << level << " [0]=" << level[0];
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
    }
  }

  return false;
}

void Script::OnRpcReturn(json &msg) {
  auto const &payload = msg["payload"];
  if (!payload.is_array() || payload.size() < 3) {
    LOG(ERROR) << "Invalid RPC return message: " << msg.dump();
    return;
  }

  const std::string &identifier = payload[0].get<std::string>();
  if (identifier != kRpcIdentifier) {
    LOG(ERROR) << "Invalid RPC return identifier: " << identifier;
    return;
  }
  int call_id = payload[1].get<int>();
  const std::string &type = payload[2].get<std::string>();

  if (type == kRpcResultOk) {
    if (payload.size() < 4) {
      LOG(ERROR) << "Invalid RPC return message: " << msg.dump();
      return;
    }
    json result = payload[3];

    std::lock_guard lock(mRpcCallMutex);
    CHECK(!mRpcCallResults.Contains(call_id));
    mRpcCallResults[call_id] = std::move(result);

    mRpcCallCondVar.notify_all();
  } else if (type == kRpcResultError) {
    if (payload.size() < 4) {
      LOG(ERROR) << "Invalid RPC error message: " << msg.dump();
      return;
    }
    json error = payload[3];

    std::lock_guard lock(mRpcCallMutex);
    CHECK(!mRpcCallResults.Contains(call_id));
    mRpcCallResults[call_id] = std::unexpected(std::move(error));

    mRpcCallCondVar.notify_all();
  } else {
    LOG(ERROR) << "Unknown RPC return type: " << type;
  }
}

void Script::ProcessMessage(const FridaScript *script, std::string_view message,
                            GBytes *data) {
  CHECK(script == mScript);

  auto msg_obj = json::parse(message);
  if (MaybeProcessSystemMessage(msg_obj)) {
    return;
  }

  LOG(DEBUG) << "Processing message " << message;
  gsize size = 0;

  std::vector<uint8_t> bytes;
  if (UNLIKELY(data != nullptr)) {
    if (const auto *pointer = g_bytes_get_data(data, &size);
        pointer != nullptr && size > 0) {
      bytes.resize(size);
      const auto *p = static_cast<const uint8_t *>(pointer);
      std::copy_n(p, size, bytes.begin());
    }
  }

  LOCK();
  for (const auto &callback : mCallbacks | std::views::values) {
    callback(this, message, bytes);
  }
}
} // namespace frida