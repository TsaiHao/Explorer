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
#include <string_view>

using nlohmann::json;

namespace plugin {
namespace {
constexpr std::string_view kScriptName = FunctionTracer::Identifier();
constexpr std::string_view kAddressKey = "address";
constexpr std::string_view kNameKey = "name";
constexpr std::array<std::string_view, 1> kIgnoreSymbolPrefixes = {"__Thumb"};

bool StartsWith(std::string_view str, std::string_view prefix) {
  return str.size() >= prefix.size() &&
         str.compare(0, prefix.size(), prefix) == 0;
}

bool ShouldIgnoreSymbol(std::string_view name) {
  return std::any_of(
      kIgnoreSymbolPrefixes.begin(), kIgnoreSymbolPrefixes.end(),
      [name](const auto &prefix) { return StartsWith(name, prefix); });
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
    CHECK(m_script == nullptr);

    auto *script = session->GetScript(kScriptName);
    if (script != nullptr) {
      m_script = script;
      return Ok();
    }

    auto status = session->CreateScript(kScriptName, kScriptSource);
    if (!status.Ok()) {
      LOGE("Failed to create script: {}", status.Message());
      return status;
    }

    script = session->GetScript(kScriptName);
    CHECK(script != nullptr);

    script->Load();
    m_script = script;

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

  frida::Script *m_script{nullptr};
};

class NativeTracerImpl : public FunctionTracer::Impl {
public:
  NativeTracerImpl() { LOGD("Creating NativeTracerImpl @ {}", (void *)this); };

  ~NativeTracerImpl() override {
    LOGD("Destroying NativeTracerImpl @ {}", (void *)this);
    if (m_script != nullptr) {
      m_script->Unload();
      m_script = nullptr;
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
      LOGE("Invalid configuration for function tracer: "
           "namespace: {}, class: {}, method: {}",
           ns, cls, method);
      return BadArgument("Invalid configuration for function tracer");
    }

    std::array<char, 128> params;
    snprintf(params.data(), params.size(), R"(["%s", "%s", "%s"])", ns.c_str(),
             cls.c_str(), method.c_str());

    frida::RpcResult result =
        m_script->RpcCallSync("resolveNativeSymbols", params.data());
    if (result.IsErr()) {
      LOGE("Failed to resolve native symbols: {}", result.UnwrapErr().dump());
      return SdkFailure("Failed to resolve native symbols");
    }

    auto const &symbols = result.Unwrap();
    if (symbols.empty()) {
      LOGW("No native symbols resolved for {}", symbols.dump());
      return NotFound("No native symbols resolved");
    }

    LOGD("Resolved {} native symbols: {}", symbols.size(), symbols.dump());
    ComposeTraceArguments(symbols, config);

    return Ok();
  }

  Status Activate() override {
    if (!m_trace_arguments.has_value()) {
      LOGE("Cannot activate tracer, maybe symbols are not resolved");
      return InvalidState("No symbols resolved");
    }

    frida::RpcResult result = m_script->RpcCallSync("traceNativeFunctions",
                                                    m_trace_arguments.value());
    if (result.IsErr()) {
      LOGE("Failed to activate native tracer: {}", result.UnwrapErr().dump());
      return SdkFailure("Failed to activate native tracer");
    }

    LOGI("Native tracer activated with arguments: {}",
         m_trace_arguments.value());
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

    LOGD("Composing trace arguments for {}", symbols.dump(1));
    for (const auto &symbol : symbols) {
      if (!symbol.contains(kAddressKey) || !symbol.contains(kNameKey)) {
        LOGE("Invalid symbol: {}", symbol.dump());
        continue;
      }
      const auto &name = symbol[kNameKey].get_ref<const std::string &>();

      if (ShouldIgnoreSymbol(name)) {
        LOGD("Ignoring symbol: {}", name);
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

    m_trace_arguments = trace_args.dump();
    LOGD("Composed trace arguments: {}", *m_trace_arguments);
  }

  std::optional<std::string> m_trace_arguments;
};

class JavaTracerImpl : public FunctionTracer::Impl {
public:
  JavaTracerImpl() { LOGD("Creating JavaTracerImpl @ {}", (void *)this); };

  ~JavaTracerImpl() override {
    LOGD("Destroying JavaTracerImpl @ {}", (void *)this);
  }

  Status Init(frida::Session *session, const nlohmann::json &config) override {
    if (Status status = Impl::Init(session, config); !status.Ok()) {
      return status;
    }

    const std::string cls = config.value("class", "");
    const std::string method = config.value("method", "");

    if (cls.empty() || method.empty()) {
      LOGE("Invalid configuration for function tracer: "
           "class: {}, method: {}",
           cls, method);
      return BadArgument("Invalid configuration for function tracer");
    }

    std::array<char, 128> params;
    snprintf(params.data(), params.size(), R"(["%s", "%s"])", cls.c_str(),
             method.c_str());
    frida::RpcResult result =
        m_script->RpcCallSync("resolveJavaSignature", params.data());

    if (result.IsErr()) {
      LOGE("Failed to resolve java symbols: {}", result.UnwrapErr().dump());
      return SdkFailure("Failed to resolve java symbols");
    }

    auto const &symbols = result.Unwrap();
    if (symbols.empty()) {
      LOGW("No java symbols resolved in rpc call {}", params.data());
      return NotFound("No java symbols resolved");
    }

    LOGD("Resolved {} java symbols: {}", symbols.size(), symbols.dump(1));
    ComposeTraceArguments(symbols, config);

    return Ok();
  }

  Status Activate() override {
    if (!m_trace_arguments.has_value()) {
      LOGE("Cannot activate tracer, maybe symbols are not resolved");
      return InvalidState("Activation failed");
    }

    frida::RpcResult result =
        m_script->RpcCallSync("traceJavaMethods", m_trace_arguments.value());
    if (result.IsErr()) {
      LOGE("Failed to activate java tracer: {}", result.UnwrapErr().dump());
      return SdkFailure("Failed to activate java tracer");
    }

    LOGI("Java tracer activated with arguments: {}", m_trace_arguments.value());
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

    m_trace_arguments = trace_args.dump();
    LOGD("Composed trace arguments: {}", *m_trace_arguments);
  }

  std::optional<std::string> m_trace_arguments;
};

FunctionTracer::FunctionTracer() = default;

FunctionTracer::~FunctionTracer() {
  LOGD("Destroying function tracer @ {}", (void *)this);
}

Status FunctionTracer::Init(frida::Session *session,
                            const nlohmann::json &config) {
  if (!config.contains("type")) {
    LOGE("Invalid configuration for function tracer: type is required");
    return BadArgument("Invalid configuration for function tracer");
  }

  const auto &type = config["type"].get_ref<const std::string &>();
  if (type == "native") {
    m_impl = std::make_unique<NativeTracerImpl>();
  } else if (type == "java") {
    m_impl = std::make_unique<JavaTracerImpl>();
  } else {
    LOGE("Invalid type for function tracer: {}", type);
    return BadArgument("Invalid type for function tracer");
  }

  return m_impl->Init(session, config);
}

Status FunctionTracer::Activate() { return m_impl->Activate(); }

Status FunctionTracer::Deactivate() { return m_impl->Deactivate(); }
} // namespace plugin