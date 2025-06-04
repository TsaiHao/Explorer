//
// Created by Hao, Zaijun on 2025/5/14.
//
#include "FunctionTracer.h"
#include "frida/Script.h"
#include "frida/Session.h"
#include "utils/Log.h"
#include "utils/Status.h"

#include "FunctionTracer.js.h"
#include <string>

FunctionTracer::FunctionTracer(): mScriptName("Tracer@" + std::to_string(reinterpret_cast<uintptr_t>(this))) {
  LOG(DEBUG) << "Creating function tracer @ " << this;
}

FunctionTracer::~FunctionTracer() {
  LOG(DEBUG) << "Destroying function tracer @ " << this;
}

Status FunctionTracer::Init(frida::Session* session, const nlohmann::json &config) {
  LOG(DEBUG) << "Initializing function tracer @ " << this;

  Status status = LoadScript(session);
  if (!status.Ok()) {
    return status;
  }

  const std::string ns = config.value("namespace", "");
  const std::string cls = config.value("class", "");
  const std::string method = config.value("method", "");

  return Ok();
}

Status FunctionTracer::Activate() {
  return Ok();
}

Status FunctionTracer::Deactivate() {
  return Ok();
}

Status FunctionTracer::LoadScript(frida::Session* session) {
  CHECK(mScript == nullptr);

  auto status = session->CreateScript(mScriptName, kScriptSource);
  if (!status.Ok()) {
    LOG(ERROR) << "Failed to create script: " << status.Message();
    return status;
  }
  
  auto* script = session->GetScript(mScriptName);
  CHECK(script != nullptr);

  script->Load();
  mScript = script;

  return Ok();
}