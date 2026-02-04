#include "StopSessionHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

StopSessionHandler::StopSessionHandler(ApplicationDaemon *daemon)
    : m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("StopSessionHandler created with null ApplicationDaemon pointer");
  }
}

void StopSessionHandler::Handle(Poco::Net::HTTPServerRequest &req,
                                Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing stop session request");

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

  // Ensure this is a stop command
  std::string action = request_json["action"];
  if (action != "stop") {
    LOGE("StopSessionHandler received non-stop action: {}", action);
    SendError(res, 400, "Handler mismatch: expected 'stop' action");
    return;
  }

  const json &data = request_json["data"];

  // Perform stop-session specific validation
  auto stop_validation = ValidateStopSessionData(data);
  if (!stop_validation.Ok()) {
    LOGE("Stop session validation failed: {}", stop_validation.Message());
    SendError(res, stop_validation);
    return;
  }

  // Extract session ID
  auto session_id_result = ExtractSessionId(data);
  if (session_id_result.IsErr()) {
    LOGE("Failed to extract session ID: {}",
         session_id_result.UnwrapErr().Message());
    SendError(res, session_id_result.UnwrapErr());
    return;
  }

  std::string session_id = session_id_result.Unwrap();
  LOGI("Stopping session: {}", session_id);

  // Process the session termination
  ProcessSessionTermination(session_id, res);
}

Status StopSessionHandler::ValidateStopSessionData(const json &data) {
  // Required: session field
  if (!data.contains("session")) {
    return BadArgument("Missing required field: 'session'");
  }

  if (!data["session"].is_string()) {
    return BadArgument("Field 'session' must be a string");
  }

  std::string session_id = data["session"];
  if (session_id.empty()) {
    return BadArgument("Field 'session' cannot be empty");
  }

  // Basic session ID format validation (should be numeric PID)
  try {
    int pid = std::stoi(session_id);
    if (pid <= 0) {
      return BadArgument("Session ID must be a positive integer");
    }
  } catch (const std::exception &e) {
    return BadArgument("Session ID must be a valid integer: " +
                       std::string(e.what()));
  }

  return Ok();
}

Result<std::string, Status>
StopSessionHandler::ExtractSessionId(const json &data) {
  if (!data.contains("session")) {
    return Err<Status>(BadArgument("Missing session field"));
  }

  if (!data["session"].is_string()) {
    return Err<Status>(BadArgument("Session field must be a string"));
  }

  std::string session_id = data["session"];
  if (session_id.empty()) {
    return Err<Status>(BadArgument("Session ID cannot be empty"));
  }

  return Ok<std::string>(session_id);
}

void StopSessionHandler::ProcessSessionTermination(
    const std::string &session_id, Poco::Net::HTTPServerResponse &res) {
  LOGI("Terminating session with ID: {}", session_id);

  if (m_daemon == nullptr) {
    LOGE("Cannot process session termination - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Call the daemon's StopSession method
  auto status = m_daemon->StopSession(session_id);

  if (!status.Ok()) {
    LOGE("Session termination failed: {}", status.Message());
    SendError(res, status);
    return;
  }

  // Success! Return confirmation
  json response_data = {
      {"session_id", session_id},
      {"stopped_at", std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count()}};

  LOGI("Session terminated successfully: {}", session_id);
  SendSuccess(res, response_data, "Session stopped successfully");
}

} // namespace http