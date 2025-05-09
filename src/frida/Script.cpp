//
// Created by Hao, Zaijun on 2025/4/27.
//

#include "Script.h"
#include "utils/Log.h"

#include "nlohmann/json.hpp"
using nlohmann::json;

#include <ranges>

#define LOCK() const std::lock_guard<std::mutex> lock(mMutex);

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

    mScript = frida_session_create_script_sync(mSession, mSource.c_str(),
                                               options, nullptr, &error);
    if (mScript == nullptr || error != nullptr) {
      LOG(ERROR) << "Failed to load script " << mName << "@" << this;
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
  CHECK(error != nullptr);

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
    LOG(INFO) << "[Client] " << message;
    return;
  case 'd':
    LOG(DEBUG) << "[Client] " << message;
    return;
  case 'w':
    LOG(WARNING) << "[Client] " << message;
    return;
  case 'e':
    LOG(ERROR) << "[Client] " << message;
    return;
  default:
    LOG(INFO) << "Unknown level " << level << " [0]=" << level[0];
  }
}

void Script::ProcessMessage(const FridaScript *script, std::string_view message,
                            GBytes *data) {
  CHECK(script == mScript) << "This script is not what we're holding";

  auto msg_obj = json::parse(message);
  if (msg_obj.is_object()) {
    if (msg_obj.contains("type") &&
        msg_obj["type"].get_ref<std::string &>() == "log") {
      WriteLogMessage(msg_obj);
      return;
    }
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