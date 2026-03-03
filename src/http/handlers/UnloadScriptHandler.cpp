#include "UnloadScriptHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

UnloadScriptHandler::UnloadScriptHandler(ApplicationDaemon *daemon)
    : m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("UnloadScriptHandler created with null ApplicationDaemon pointer");
  }
}

void UnloadScriptHandler::Handle(Poco::Net::HTTPServerRequest &req,
                                 Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing unload script request");

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

  // Ensure this is an unload_script command
  std::string action = request_json["action"];
  if (action != "unload_script") {
    LOGE("UnloadScriptHandler received non-unload_script action: {}", action);
    SendError(res, 400, "Handler mismatch: expected 'unload_script' action");
    return;
  }

  const json &data = request_json["data"];

  // Extract session ID and script name
  std::string session_id = data["session"];
  std::string script_name = data["script"];

  if (m_daemon == nullptr) {
    LOGE("Cannot unload script - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Unload the script
  auto status = m_daemon->UnloadScript(session_id, script_name);

  if (!status.Ok()) {
    LOGE("Failed to unload script: {}", status.Message());
    SendError(res, status);
    return;
  }

  json response_data = {{"session_id", session_id},
                         {"script", script_name}};

  LOGI("Script unloaded successfully for session: {}", session_id);
  SendSuccess(res, response_data, "Script unloaded successfully");
}

} // namespace http
