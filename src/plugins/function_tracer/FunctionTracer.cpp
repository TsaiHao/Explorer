//
// Created by Hao, Zaijun on 2025/5/14.
//
#include "FunctionTracer.h"
#include "frida/Script.h"
#include "frida/Session.h"
#include "utils/Log.h"
#include "utils/Status.h"

constexpr std::string_view SCRIPT_SOURCE =
  R"jscode(
#include "FunctionTracer.js"
)jscode";

FunctionTracer::FunctionTracer() {
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

}

Status FunctionTracer::Deactivate() {

}

Status FunctionTracer::LoadScript(frida::Session* session) {
  CHECK(mScript == nullptr);

  const std::string script_name = "Tracer@" + std::to_string(reinterpret_cast<uintptr_t>(this)); 
  auto status = session->CreateScript(script_name, SCRIPT_SOURCE);
  if (!status.Ok()) {
    LOG(ERROR) << "Failed to create script: " << status.Message();
    return status;
  }
  
  auto* script = session->GetScript(script_name);
  CHECK(script != nullptr);

  script->Load();
  mScript = script;

  return Ok();
}