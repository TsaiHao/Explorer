#include "StatusHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

StatusHandler::StatusHandler(ApplicationDaemon *daemon) : m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("StatusHandler created with null ApplicationDaemon pointer");
  }
}

void StatusHandler::Handle(Poco::Net::HTTPServerRequest &req,
                           Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing status query request");

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

  // Ensure this is a status command
  std::string action = request_json["action"];
  if (action != "status") {
    LOGE("StatusHandler received non-status action: {}", action);
    SendError(res, 400, "Handler mismatch: expected 'status' action");
    return;
  }

  const json &data = request_json["data"];

  // Perform status query specific validation
  auto status_validation = ValidateStatusData(data);
  if (!status_validation.Ok()) {
    LOGE("Status query validation failed: {}", status_validation.Message());
    SendError(res, status_validation);
    return;
  }

  // Extract session ID (optional - empty string means global status)
  std::string session_id = ExtractSessionId(data);

  if (session_id.empty()) {
    LOGI("Querying global daemon status");
  } else {
    LOGI("Querying status for session: {}", session_id);
  }

  // Process the status query
  ProcessStatusQuery(session_id, res);
}

Status StatusHandler::ValidateStatusData(const json &data) {
  // The data object can be empty for global status queries
  if (!data.is_object()) {
    return BadArgument("Data field must be an object");
  }

  // If session field is present, validate it
  if (data.contains("session")) {
    if (data["session"].is_null()) {
      // Null session is treated as global status request
      return Ok();
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
  }

  return Ok();
}

std::string StatusHandler::ExtractSessionId(const json &data) {
  if (!data.contains("session") || data["session"].is_null()) {
    return ""; // Empty string indicates global status query
  }

  if (!data["session"].is_string()) {
    return ""; // Invalid format, treat as global status
  }

  return data["session"].get<std::string>();
}

void StatusHandler::ProcessStatusQuery(const std::string &session_id,
                                       Poco::Net::HTTPServerResponse &res) {
  if (m_daemon == nullptr) {
    LOGE("Cannot process status query - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Call the daemon's GetSessionStatus method
  auto result = m_daemon->GetSessionStatus(session_id);

  if (result.IsErr()) {
    LOGE("Status query failed: {}", result.UnwrapErr().Message());
    SendError(res, result.UnwrapErr());
    return;
  }

  // Success! Return the status data
  json status_data = result.Unwrap();

  std::string message = session_id.empty()
                            ? "Global status retrieved successfully"
                            : "Session status retrieved successfully";

  LOGI("Status query successful for {}",
       session_id.empty() ? "global status" : ("session " + session_id));
  SendSuccess(res, status_data, message);
}

} // namespace http