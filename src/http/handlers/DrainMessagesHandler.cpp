#include "DrainMessagesHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

DrainMessagesHandler::DrainMessagesHandler(ApplicationDaemon *daemon)
    : m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("DrainMessagesHandler created with null ApplicationDaemon pointer");
  }
}

void DrainMessagesHandler::Handle(Poco::Net::HTTPServerRequest &req,
                                  Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing drain messages request");

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

  // Ensure this is a drain command
  std::string action = request_json["action"];
  if (action != "drain") {
    LOGE("DrainMessagesHandler received non-drain action: {}", action);
    SendError(res, 400, "Handler mismatch: expected 'drain' action");
    return;
  }

  const json &data = request_json["data"];

  // Extract session ID
  if (!data.contains("session") || !data["session"].is_string()) {
    SendError(res, 400, "Missing or invalid 'session' field");
    return;
  }

  std::string session_id = data["session"];
  if (session_id.empty()) {
    SendError(res, 400, "Field 'session' cannot be empty");
    return;
  }

  if (m_daemon == nullptr) {
    LOGE("Cannot drain messages - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Drain messages from the session
  auto result = m_daemon->DrainSessionMessages(session_id);

  if (result.IsErr()) {
    LOGE("Failed to drain messages: {}", result.UnwrapErr().Message());
    SendError(res, result.UnwrapErr());
    return;
  }

  LOGI("Messages drained successfully for session: {}", session_id);
  SendSuccess(res, result.Unwrap(), "Messages drained successfully");
}

} // namespace http
