#include "ListSessionsHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

ListSessionsHandler::ListSessionsHandler(ApplicationDaemon *daemon)
    : m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("ListSessionsHandler created with null ApplicationDaemon pointer");
  }
}

void ListSessionsHandler::Handle(Poco::Net::HTTPServerRequest &req,
                                 Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing list sessions request");

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

  // Ensure this is a list command
  std::string action = request_json["action"];
  if (action != "list") {
    LOGE("ListSessionsHandler received non-list action: {}", action);
    SendError(res, 400, "Handler mismatch: expected 'list' action");
    return;
  }

  const json &data = request_json["data"];

  // Perform list sessions specific validation
  auto list_validation = ValidateListData(data);
  if (!list_validation.Ok()) {
    LOGE("List sessions validation failed: {}", list_validation.Message());
    SendError(res, list_validation);
    return;
  }

  // Extract filter criteria
  json filter = ExtractFilterCriteria(data);

  // Validate filter criteria
  auto filter_validation = ValidateFilterCriteria(filter);
  if (!filter_validation.Ok()) {
    LOGE("Filter criteria validation failed: {}", filter_validation.Message());
    SendError(res, filter_validation);
    return;
  }

  LOGI("Listing sessions with filter: {}", filter.dump());

  // Process the session listing
  ProcessSessionListing(filter, res);
}

Status ListSessionsHandler::ValidateListData(const json &data) {
  // The data object can be empty for list all sessions
  if (!data.is_object()) {
    return BadArgument("Data field must be an object");
  }

  // Check if filter field is present and valid
  if (data.contains("filter")) {
    if (!data["filter"].is_object()) {
      return BadArgument("Field 'filter' must be an object");
    }
  }

  return Ok();
}

json ListSessionsHandler::ExtractFilterCriteria(const json &data) {
  if (!data.contains("filter")) {
    return json::object(); // Return empty filter object
  }

  const json &filter = data["filter"];
  if (!filter.is_object()) {
    return json::object(); // Return empty filter if invalid
  }

  return filter;
}

Status ListSessionsHandler::ValidateFilterCriteria(const json &filter) {
  if (!filter.is_object()) {
    return BadArgument("Filter must be an object");
  }

  // Validate supported filter fields
  for (const auto &[key, value] : filter.items()) {
    // Check for supported filter keys
    if (key != "app" && key != "status" && key != "pid") {
      LOGW("Unsupported filter key: {}", key);
      // Don't fail validation, just warn - unknown filters will be ignored
      continue;
    }

    // Validate filter values
    if (key == "app") {
      if (!value.is_string()) {
        return BadArgument("Filter 'app' must be a string");
      }
      if (value.get<std::string>().empty()) {
        return BadArgument("Filter 'app' cannot be empty");
      }
    } else if (key == "status") {
      if (!value.is_string()) {
        return BadArgument("Filter 'status' must be a string");
      }
      std::string status_val = value.get<std::string>();
      if (status_val != "active" && status_val != "terminated") {
        return BadArgument("Filter 'status' must be 'active' or 'terminated'");
      }
    } else if (key == "pid") {
      if (!value.is_number_integer()) {
        return BadArgument("Filter 'pid' must be an integer");
      }
      int pid = value.get<int>();
      if (pid <= 0) {
        return BadArgument("Filter 'pid' must be a positive integer");
      }
    }
  }

  return Ok();
}

void ListSessionsHandler::ProcessSessionListing(
    const json &filter, Poco::Net::HTTPServerResponse &res) {
  if (m_daemon == nullptr) {
    LOGE("Cannot process session listing - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Call the daemon's ListSessions method
  auto result = m_daemon->ListSessions(filter);

  if (result.IsErr()) {
    LOGE("Session listing failed: {}", result.UnwrapErr().Message());
    SendError(res, result.UnwrapErr());
    return;
  }

  // Success! Return the sessions list
  json sessions_data = result.Unwrap();

  // Log summary
  size_t session_count = 0;
  if (sessions_data.contains("total_count")) {
    session_count = sessions_data["total_count"];
  }

  LOGI("Listed {} sessions successfully", session_count);

  std::string message = "Sessions listed successfully";
  if (session_count == 0) {
    message = "No sessions found";
  } else if (session_count == 1) {
    message = "1 session found";
  } else {
    message = std::to_string(session_count) + " sessions found";
  }

  SendSuccess(res, sessions_data, message);
}

} // namespace http