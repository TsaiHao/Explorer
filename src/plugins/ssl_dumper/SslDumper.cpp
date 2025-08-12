//
// Created by Hao, Zaijun on 2025/7/16.
//

#include "SslDumper.h"

#include "SslDumper.js.h"
#include "frida/Session.h"
#include "utils/Log.h"
#include "utils/Status.h"
#include <memory>

namespace plugin {
namespace {
constexpr std::string_view kOutputKey = "output";
constexpr std::string_view kScriptName = SslDumper::Identifier();
constexpr std::string_view kCallbackName = "SslDataSink";

class SimpleBinFileWriter {
public:
  Status Init(std::string_view path) {
    m_file = fopen(path.data(), "wb");
    if (m_file == nullptr) {
      return InvalidOperation("Failed to open file for writing");
    }
    return Ok();
  }

  ~SimpleBinFileWriter() {
    if (LIKELY(m_file != nullptr)) {
      fclose(m_file);
    }
  }

  void Write(const uint8_t *data, size_t size) {
    if (LIKELY(m_file != nullptr)) {
      fwrite(data, 1, size, m_file);
      m_written_size += size;
    }
  }

  size_t WrittenSize() const { return m_written_size; }

private:
  FILE *m_file = nullptr;
  size_t m_written_size = 0;
};
} // namespace

class SslDumper::Impl {
public:
  Impl() : m_file_writer(std::make_unique<SimpleBinFileWriter>()) {
    LOG(INFO) << "Creating SslDumper::Impl";
  }
  ~Impl() { Deactivate(); }

  Status Init(frida::Session *session, const nlohmann::json &config) {
    m_session = session;
    if (config.contains(kOutputKey)) {
      auto const &output_path =
          config[kOutputKey].get_ref<const std::string &>();
      auto status = m_file_writer->Init(output_path);
      if (!status.Ok()) {
        return status;
      }
      LOG(DEBUG) << "Initialized SslDumper with output path: " << output_path;
    } else {
      return BadArgument("Missing output path in configuration");
    }
    return Ok();
  }

  Status Activate() {
    if (m_session == nullptr) {
      return InvalidState("Session is not initialized");
    }

    auto *script = m_session->GetScript(kScriptName);
    if (script != nullptr) {
      LOG(DEBUG) << "Script already loaded: " << kScriptName
                 << ", skipping activation.";
      return Ok();
    }

    CHECK_STATUS(m_session->CreateScript(kScriptName, kScriptSource));
    script = m_session->GetScript(kScriptName);
    CHECK(script != nullptr);

    m_script = script;

    script->AddMessageCallback(
        kCallbackName,
        [this](const frida::Script *script, const nlohmann::json &msg,
               const uint8_t *data,
               size_t size) { OnSslDataSink(script, msg, data, size); });

    script->Load();

    auto result = script->RpcCallSync("init", "");
    if (!result) {
      LOG(ERROR) << "Failed to init SslDumper script: "
                 << result.error().dump();
      return SdkFailure("Failed to init SslDumper script");
    }

    result = script->RpcCallSync("start", "");
    if (!result) {
      LOG(ERROR) << "Failed to start SslDumper: " << result.error().dump();
      return SdkFailure("Failed to start SslDumper");
    }

    LOG(DEBUG) << "SslDumper activated, script loaded: " << kScriptName;
    return Ok();
  }

  Status Deactivate() {
    if (m_script != nullptr) {
      auto result = m_script->RpcCallSync("stop", "");
      if (!result) {
        LOG(ERROR) << "Failed to stop SslDumper: " << result.error().dump();
        return SdkFailure("Failed to stop SslDumper");
      }
      m_session->RemoveScript(kScriptName);
      m_script = nullptr;
    }
    if (m_file_writer != nullptr) {
      m_file_writer.reset();
    }

    LOG(DEBUG) << "SslDumper deactivated";
    return Ok();
  }

private:
  void OnSslDataSink(const frida::Script *script, const nlohmann::json &msg,
                     const uint8_t *data, size_t size) {
    if (UNLIKELY(script != m_script)) {
      LOG(ERROR) << "Received SSL data for an unknown script: " << script;
      return;
    }

    if (data == nullptr || size == 0) {
      LOG(WARNING) << "Received empty SSL data: " << msg.dump();
      return;
    }

    auto size32 = static_cast<uint32_t>(size);
    m_file_writer->Write(reinterpret_cast<const uint8_t *>(&size32), sizeof(size32));

    m_file_writer->Write(data, size);
    LOG(DEBUG) << "(SslDumper) Wrote " << size
               << " bytes of SSL data to file, total written: "
               << m_file_writer->WrittenSize() << " bytes";
  }

  frida::Session *m_session = nullptr;
  std::unique_ptr<SimpleBinFileWriter> m_file_writer;
  frida::Script *m_script = nullptr;
};

SslDumper::SslDumper() : m_impl(std::make_unique<SslDumper::Impl>()) {}

SslDumper::~SslDumper() = default;

Status SslDumper::Init(frida::Session *session, const nlohmann::json &config) {
  return m_impl->Init(session, config);
}

Status SslDumper::Activate() { return m_impl->Activate(); }

Status SslDumper::Deactivate() { return m_impl->Deactivate(); }

} // namespace plugin