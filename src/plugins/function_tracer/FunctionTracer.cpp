//
// Created by Hao, Zaijun on 2025/5/14.
//
#include "FunctionTracer.h"
#include "frida/Script.h"
#include "frida/Session.h"
#include "utils/Log.h"
#include "utils/Status.h"

#include "FunctionTracer.js.h"
#include "utils/System.h"
#include <string>

using nlohmann::json;

namespace plugin {
namespace {
constexpr std::string_view kScriptName = FunctionTracer::Identifier();
constexpr std::string_view kAddressKey = "address";
constexpr std::string_view kNameKey = "name";
constexpr std::array<std::string_view, 1> kIgnoreSymbolPrefixes = {"__Thumb"};

bool ShouldIgnoreSymbol(std::string_view name) {
  return std::ranges::any_of(kIgnoreSymbolPrefixes, [name](const auto &prefix) {
    return name.starts_with(prefix);
  });
}
} // namespace

class FunctionTracer::Impl {
public:
  Impl() = default;
  virtual ~Impl() = default;

  virtual Status Init(frida::Session *session, const nlohmann::json &) {
    return LoadScript(session);
  }

  virtual Status Activate() { return Ok(); };
  virtual Status Deactivate() { return Ok(); };

protected:
  Status LoadScript(frida::Session *session) {
    CHECK(mScript == nullptr);

    auto *script = session->GetScript(kScriptName);
    if (script != nullptr) {
      mScript = script;
      return Ok();
    }

    auto status = session->CreateScript(kScriptName, kScriptSource);
    if (!status.Ok()) {
      LOG(ERROR) << "Failed to create script: " << status.Message();
      return status;
    }

    script = session->GetScript(kScriptName);
    CHECK(script != nullptr);

    script->Load();
    mScript = script;

    return Ok();
  }

  static json ComposeTraceConfig(const json &config) {
    json trace_config;
    trace_config["bt"] = config.value("backtrace", false);
    trace_config["args"] = config.value("arguments", false);
    trace_config["atrace"] = config.value("atrace", false);
    trace_config["log"] = config.value("log", false);

    return trace_config;
  }

  frida::Script *mScript{nullptr};
};

class NativeTracerImpl : public FunctionTracer::Impl {
public:
  NativeTracerImpl() { LOG(DEBUG) << "Creating NativeTracerImpl @ " << this; };

  ~NativeTracerImpl() override {
    LOG(DEBUG) << "Destroying NativeTracerImpl @ " << this;
    if (mScript != nullptr) {
      mScript->Unload();
      mScript = nullptr;
    }
  }

  Status Init(frida::Session *session, const nlohmann::json &config) override {
    if (Status status = Impl::Init(session, config); !status.Ok()) {
      return status;
    }

    const std::string ns = config.value("namespace", "");
    const std::string cls = config.value("class", "");
    const std::string method = config.value("method", "");

    if (ns.empty() && cls.empty() && method.empty()) {
      LOG(ERROR) << "Invalid configuration for function tracer: "
                 << "namespace: " << ns << ", class: " << cls
                 << ", method: " << method;
      return BadArgument("Invalid configuration for function tracer");
    }

    std::array<char, 128> params;
    snprintf(params.data(), params.size(), R"(["%s", "%s", "%s"])", ns.c_str(),
             cls.c_str(), method.c_str());
    frida::RpcResult symbols =
        mScript->RpcCallSync("resolveNativeSymbols", params.data());
    if (!symbols) {
      LOG(ERROR) << "Failed to resolve native symbols: "
                 << symbols.error().dump();
      return SdkFailure("Failed to resolve native symbols");
    }
    if (symbols->empty()) {
      LOG(WARNING) << "No native symbols resolved for "
                   << "namespace: " << ns << ", class: " << cls
                   << ", method: " << method;
      return NotFound("No native symbols resolved");
    }

    LOG(DEBUG) << "Resolved " << symbols.value().size() << " native symbols: ";
    ComposeTraceArguments(symbols.value(), config);

    return Ok();
  }

  Status Activate() override {
    if (!mTraceArguments.has_value()) {
      LOG(ERROR) << "Cannot activate tracer, maybe symbols are not resolved";
      return InvalidState("No symbols resolved");
    }

    frida::RpcResult result =
        mScript->RpcCallSync("traceNativeFunctions", mTraceArguments.value());
    if (!result) {
      LOG(ERROR) << "Failed to activate native tracer: "
                 << result.error().dump();
      return SdkFailure("Failed to activate native tracer");
    }

    LOG(INFO) << "Native tracer activated with arguments: "
              << mTraceArguments.value();
    return Ok();
  }

private:
  void ComposeTraceArguments(const json &symbols, const json &config) {
    if (symbols.empty()) {
      return;
    }

    std::vector<intptr_t> addrs;
    std::vector<std::string> identifiers;
    json trace_config = ComposeTraceConfig(config);

    LOG(DEBUG) << "Composing trace arguments for " << symbols.dump(1);
    for (const auto &symbol : symbols) {
      if (!symbol.contains(kAddressKey) || !symbol.contains(kNameKey)) {
        LOG(ERROR) << "Invalid symbol: " << symbol.dump();
        continue;
      }
      const auto &name = symbol[kNameKey].get_ref<const std::string &>();

      if (ShouldIgnoreSymbol(name)) {
        LOG(DEBUG) << "Ignoring symbol: " << name;
        continue;
      }

      auto const &address_hex =
          symbol[kAddressKey].get_ref<const std::string &>();
      auto const &address = std::stoll(address_hex, nullptr, 16);

      addrs.push_back(static_cast<intptr_t>(address));
      std::string identifier = utils::DemangleSymbol(name);
      identifiers.emplace_back(std::move(identifier));
    }

    json trace_args;
    trace_args.emplace_back(std::move(addrs));
    trace_args.emplace_back(std::move(identifiers));
    trace_args.emplace_back(std::move(trace_config));

    mTraceArguments = trace_args.dump();
    LOG(DEBUG) << "Composed trace arguments: " << *mTraceArguments;
  }

  std::optional<std::string> mTraceArguments;
};

class JavaTracerImpl : public FunctionTracer::Impl {
public:
  JavaTracerImpl() { LOG(DEBUG) << "Creating JavaTracerImpl @ " << this; };

  ~JavaTracerImpl() override {
    LOG(DEBUG) << "Destroying JavaTracerImpl @ " << this;
  }

  Status Init(frida::Session *session, const nlohmann::json &config) override {
    if (Status status = Impl::Init(session, config); !status.Ok()) {
      return status;
    }

    const std::string cls = config.value("class", "");
    const std::string method = config.value("method", "");

    if (cls.empty() || method.empty()) {
      LOG(ERROR) << "Invalid configuration for function tracer: "
                 << "class: " << cls << ", method: " << method;
      return BadArgument("Invalid configuration for function tracer");
    }

    std::array<char, 128> params;
    snprintf(params.data(), params.size(), R"(["%s", "%s"])", cls.c_str(),
             method.c_str());
    frida::RpcResult symbols =
        mScript->RpcCallSync("resolveJavaSignature", params.data());
    if (!symbols) {
      LOG(ERROR) << "Failed to resolve java symbols: "
                 << symbols.error().dump();
      return SdkFailure("Failed to resolve java symbols");
    }
    if (symbols->empty()) {
      LOG(WARNING) << "No java symbols resolved for "
                   << "class: " << cls << ", method: " << method;
      return NotFound("No java symbols resolved");
    }

    LOG(DEBUG) << "Resolved " << symbols.value().size()
               << " java symbols: " << symbols.value().dump(1);
    ComposeTraceArguments(symbols.value(), config);

    return Ok();
  }

  Status Activate() override {
    if (!mTraceArguments.has_value()) {
      LOG(ERROR) << "Cannot activate tracer, maybe symbols are not resolved";
      return InvalidState("Activation failed");
    }

    frida::RpcResult result =
        mScript->RpcCallSync("traceJavaMethods", mTraceArguments.value());
    if (!result) {
      LOG(ERROR) << "Failed to activate java tracer: " << result.error().dump();
      return SdkFailure("Failed to activate java tracer");
    }

    LOG(INFO) << "Java tracer activated with arguments: "
              << mTraceArguments.value();
    return Ok();
  }

private:
  void ComposeTraceArguments(const json &symbols, const json &config) {
    if (symbols.empty()) {
      return;
    }

    json trace_config = ComposeTraceConfig(config);
    json trace_args;
    trace_args.emplace_back(symbols);
    trace_args.emplace_back(trace_config);

    mTraceArguments = trace_args.dump();
    LOG(DEBUG) << "Composed trace arguments: " << *mTraceArguments;
  }

  std::optional<std::string> mTraceArguments;
};

FunctionTracer::FunctionTracer() = default;

FunctionTracer::~FunctionTracer() {
  LOG(DEBUG) << "Destroying function tracer @ " << this;
}

Status FunctionTracer::Init(frida::Session *session,
                            const nlohmann::json &config) {
  if (!config.contains("type")) {
    LOG(ERROR) << "Invalid configuration for function tracer: "
               << "type is required";
    return BadArgument("Invalid configuration for function tracer");
  }

  const auto &type = config["type"].get_ref<const std::string &>();
  if (type == "native") {
    mImpl = std::make_unique<NativeTracerImpl>();
  } else if (type == "java") {
    mImpl = std::make_unique<JavaTracerImpl>();
  } else {
    LOG(ERROR) << "Invalid type for function tracer: " << type;
    return BadArgument("Invalid type for function tracer");
  }

  return mImpl->Init(session, config);
}

Status FunctionTracer::Activate() { return mImpl->Activate(); }

Status FunctionTracer::Deactivate() { return mImpl->Deactivate(); }
} // namespace plugin