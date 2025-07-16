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
    mFile = fopen(path.data(), "wb");
    if (mFile == nullptr) {
      return InvalidOperation("Failed to open file for writing");
    }
    return Ok();
  }

  ~SimpleBinFileWriter() {
    if (LIKELY(mFile != nullptr)) {
      fclose(mFile);
    }
  }

  void Write(const uint8_t *data, size_t size) {
    if (LIKELY(mFile != nullptr)) {
      fwrite(data, 1, size, mFile);
      mWrittenSize += size;
    }
  }

  size_t WrittenSize() const { return mWrittenSize; }

private:
  FILE *mFile = nullptr;
  size_t mWrittenSize = 0;
};
} // namespace

class SslDumper::Impl {
public:
  Impl() : mFileWriter(std::make_unique<SimpleBinFileWriter>()) {
    LOG(INFO) << "Creating SslDumper::Impl";
  }
  ~Impl() {
    Deactivate();
  }

  Status Init(frida::Session *session, const nlohmann::json &config) {
    mSession = session;
    if (config.contains(kOutputKey)) {
      auto const &output_path = config[kOutputKey].get_ref<const std::string &>();
      auto status = mFileWriter->Init(output_path);
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
    if (mSession == nullptr) {
      return InvalidState("Session is not initialized");
    }

    auto *script = mSession->GetScript(kScriptName);
    if (script != nullptr) {
      LOG(DEBUG) << "Script already loaded: " << kScriptName
                 << ", skipping activation.";
      return Ok();
    }

    CHECK_STATUS(mSession->CreateScript(kScriptName, kScriptSource));
    script = mSession->GetScript(kScriptName);
    CHECK(script != nullptr);

    mScript = script;

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
    if (mScript != nullptr) {
      auto result = mScript->RpcCallSync("stop", "");
      if (!result) {
        LOG(ERROR) << "Failed to stop SslDumper: " << result.error().dump();
        return SdkFailure("Failed to stop SslDumper");
      }
      mSession->RemoveScript(kScriptName);
      mScript = nullptr;
    }
    if (mFileWriter != nullptr) {
      mFileWriter.reset();
    }

    LOG(DEBUG) << "SslDumper deactivated";
    return Ok();
  }

private:
  void OnSslDataSink(const frida::Script *script, const nlohmann::json &msg,
                     const uint8_t *data, size_t size) {
    if (UNLIKELY(script != mScript)) {
      LOG(ERROR) << "Received SSL data for an unknown script: " << script;
      return;
    }

    if (data == nullptr || size == 0) {
      LOG(WARNING) << "Received empty SSL data: " << msg.dump();
      return;
    }

    mFileWriter->Write(data, size);
    LOG(DEBUG) << "(SslDumper) Wrote " << size
               << " bytes of SSL data to file, total written: "
               << mFileWriter->WrittenSize() << " bytes";
  }

  frida::Session *mSession = nullptr;
  std::unique_ptr<SimpleBinFileWriter> mFileWriter;
  frida::Script *mScript = nullptr;
};

SslDumper::SslDumper() : mImpl(std::make_unique<SslDumper::Impl>()) {}

SslDumper::~SslDumper() = default;

Status SslDumper::Init(frida::Session *session, const nlohmann::json &config) {
  return mImpl->Init(session, config);
}

Status SslDumper::Activate() {
  return mImpl->Activate();
}

Status SslDumper::Deactivate() {
  return mImpl->Deactivate();
}

} // namespace plugin