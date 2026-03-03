#include "LoadScriptHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

LoadScriptHandler::LoadScriptHandler(ApplicationDaemon *daemon)
    : m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("LoadScriptHandler created with null ApplicationDaemon pointer");
  }
}

void LoadScriptHandler::Handle(Poco::Net::HTTPServerRequest &req,
                               Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing load script request");

  // Parse JSON request
  auto json_result = ParseRequestJson(req);
  if (json_result.IsErr()) {
    LOGE("Failed to parse JSON request: {}", json_result.UnwrapErr().Message());
    SendError(res, json_result.UnwrapErr());
    return;
  }

  auto request_json = json_result.Unwrap();

  // Validate request schema
  auto validation_status = ApiSchema::ValidateRequest(request_json);
  if (!validation_status.Ok()) {
    LOGE("Request validation failed: {}", validation_status.Message());
    SendError(res, validation_status);
    return;
  }

  // Ensure this is a load_script command
  std::string action = request_json["action"];
  if (action != "load_script") {
    LOGE("LoadScriptHandler received non-load_script action: {}", action);
    SendError(res, 400, "Handler mismatch: expected 'load_script' action");
    return;
  }

  const json &data = request_json["data"];

  // Extract session ID
  std::string session_id = data["session"];

  // Extract script name and source
  std::string script_name;
  std::string script_source;

  if (data.contains("script")) {
    script_name = data["script"].get<std::string>();
    // Source will be read from file by the Device/Session layer
    script_source = "";
  } else {
    // Inline script - generate a name with timestamp
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    script_name = "inline_script_" + std::to_string(now);
    script_source = data["script_source"].get<std::string>();
  }

  if (m_daemon == nullptr) {
    LOGE("Cannot load script - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Load the script
  auto result = m_daemon->LoadScript(session_id, script_name, script_source);

  if (result.IsErr()) {
    LOGE("Failed to load script: {}", result.UnwrapErr().Message());
    SendError(res, result.UnwrapErr());
    return;
  }

  LOGI("Script loaded successfully for session: {}", session_id);
  SendSuccess(res, result.Unwrap(), "Script loaded successfully");
}

} // namespace http
