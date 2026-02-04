#include "ApiSchema.h"
#include "utils/Log.h"

namespace http {

Result<ApiCommand, Status> ApiSchema::ParseCommand(const std::string &action) {
  if (action == "start") {
    return Ok<ApiCommand>(ApiCommand::kStart);
  } else if (action == "stop") {
    return Ok<ApiCommand>(ApiCommand::kStop);
  } else if (action == "status") {
    return Ok<ApiCommand>(ApiCommand::kStatus);
  } else if (action == "list") {
    return Ok<ApiCommand>(ApiCommand::kList);
  } else if (action == "drain") {
    return Ok<ApiCommand>(ApiCommand::kDrain);
  } else {
    return Err<Status>(BadArgument("Unknown action: " + action));
  }
}

std::string ApiSchema::CommandToString(ApiCommand command) {
  switch (command) {
  case ApiCommand::kStart:
    return "start";
  case ApiCommand::kStop:
    return "stop";
  case ApiCommand::kStatus:
    return "status";
  case ApiCommand::kList:
    return "list";
  case ApiCommand::kDrain:
    return "drain";
  }
  return "unknown";
}

Status ApiSchema::ValidateRequest(const json &request_json) {
  // Check top-level structure
  if (!request_json.is_object()) {
    return BadArgument("Request must be a JSON object");
  }

  // Check required "action" field
  if (!request_json.contains("action")) {
    return BadArgument("Missing required field: action");
  }

  auto action_status =
      CheckFieldType(request_json["action"], json::value_t::string, "action");
  if (!action_status.Ok()) {
    return action_status;
  }

  // Parse and validate action
  std::string action = request_json["action"];
  auto command_result = ParseCommand(action);
  if (command_result.IsErr()) {
    return command_result.UnwrapErr();
  }

  // Check required "data" field
  if (!request_json.contains("data")) {
    return BadArgument("Missing required field: data");
  }

  auto data_status =
      CheckFieldType(request_json["data"], json::value_t::object, "data");
  if (!data_status.Ok()) {
    return data_status;
  }

  // Validate data based on command type
  ApiCommand command = command_result.Unwrap();
  const json &data = request_json["data"];

  switch (command) {
  case ApiCommand::kStart:
    return ValidateStartRequest(data);
  case ApiCommand::kStop:
    return ValidateStopRequest(data);
  case ApiCommand::kStatus:
    return ValidateStatusRequest(data);
  case ApiCommand::kList:
    return ValidateListRequest(data);
  case ApiCommand::kDrain:
    return ValidateDrainRequest(data);
  }

  return Ok();
}

Status ApiSchema::ValidateStartRequest(const json &data) {
  // Either "app" or "pid" is required for targeting
  if (!data.contains("app") && !data.contains("pid")) {
    return BadArgument("Start request requires either 'app' or 'pid' field");
  }

  // Validate app field if present
  if (data.contains("app")) {
    auto app_status = CheckFieldType(data["app"], json::value_t::string, "app");
    if (!app_status.Ok()) {
      return app_status;
    }

    std::string app = data["app"];
    if (app.empty()) {
      return BadArgument("Field 'app' cannot be empty");
    }
  }

  // Validate pid field if present
  if (data.contains("pid")) {
    auto pid_status =
        CheckFieldType(data["pid"], json::value_t::number_integer, "pid");
    if (!pid_status.Ok()) {
      return pid_status;
    }

    int pid = data["pid"];
    if (pid <= 0) {
      return BadArgument("Field 'pid' must be a positive integer");
    }
  }

  // Validate optional fields
  if (data.contains("spawn")) {
    auto spawn_status =
        CheckFieldType(data["spawn"], json::value_t::boolean, "spawn");
    if (!spawn_status.Ok()) {
      return spawn_status;
    }
  }

  if (data.contains("am_start")) {
    auto am_start_status =
        CheckFieldType(data["am_start"], json::value_t::string, "am_start");
    if (!am_start_status.Ok()) {
      return am_start_status;
    }
  }

  if (data.contains("scripts")) {
    auto scripts_status =
        CheckFieldType(data["scripts"], json::value_t::array, "scripts");
    if (!scripts_status.Ok()) {
      return scripts_status;
    }

    // Validate each script path
    for (const auto &script : data["scripts"]) {
      if (!script.is_string()) {
        return BadArgument("All script paths must be strings");
      }
    }
  }

  if (data.contains("script_source")) {
    auto script_source_status = CheckFieldType(
        data["script_source"], json::value_t::string, "script_source");
    if (!script_source_status.Ok()) {
      return script_source_status;
    }
  }

  if (data.contains("trace")) {
    return ValidateTraceConfig(data["trace"]);
  }

  if (data.contains("ssl_dumper")) {
    auto ssl_status =
        CheckFieldType(data["ssl_dumper"], json::value_t::object, "ssl_dumper");
    if (!ssl_status.Ok()) {
      return ssl_status;
    }
  }

  return Ok();
}

Status ApiSchema::ValidateStopRequest(const json &data) {
  // Required session identifier
  if (!data.contains("session")) {
    return BadArgument("Stop request requires 'session' field");
  }

  auto session_status =
      CheckFieldType(data["session"], json::value_t::string, "session");
  if (!session_status.Ok()) {
    return session_status;
  }

  std::string session = data["session"];
  if (session.empty()) {
    return BadArgument("Field 'session' cannot be empty");
  }

  return Ok();
}

Status ApiSchema::ValidateStatusRequest(const json &data) {
  // Optional session identifier (if not provided, returns global status)
  if (data.contains("session")) {
    auto session_status =
        CheckFieldType(data["session"], json::value_t::string, "session");
    if (!session_status.Ok()) {
      return session_status;
    }

    std::string session = data["session"];
    if (session.empty()) {
      return BadArgument("Field 'session' cannot be empty");
    }
  }

  return Ok();
}

Status ApiSchema::ValidateListRequest(const json &data) {
  // List request data is typically empty, but we allow optional filters
  if (data.contains("filter")) {
    auto filter_status =
        CheckFieldType(data["filter"], json::value_t::object, "filter");
    if (!filter_status.Ok()) {
      return filter_status;
    }
  }

  return Ok();
}

Status ApiSchema::ValidateDrainRequest(const json &data) {
  // Required session identifier
  if (!data.contains("session")) {
    return BadArgument("Drain request requires 'session' field");
  }

  auto session_status =
      CheckFieldType(data["session"], json::value_t::string, "session");
  if (!session_status.Ok()) {
    return session_status;
  }

  std::string session = data["session"];
  if (session.empty()) {
    return BadArgument("Field 'session' cannot be empty");
  }

  return Ok();
}

json ApiSchema::CreateSuccessResponse(const json &data,
                                      const std::string &message) {
  json response = {{"status", "success"}, {"data", data}};

  if (!message.empty()) {
    response["message"] = message;
  }

  return response;
}

json ApiSchema::CreateErrorResponse(const std::string &message,
                                    const std::string &error_code,
                                    const json &details) {
  json response = {{"status", "error"}, {"message", message}};

  if (!error_code.empty()) {
    response["error_code"] = error_code;
  }

  if (!details.empty()) {
    response["details"] = details;
  }

  return response;
}

json ApiSchema::GetRequestSchema() {
  return json{{"$schema", "http://json-schema.org/draft-07/schema#"},
              {"title", "Explorer Daemon API Request"},
              {"type", "object"},
              {"required", {"action", "data"}},
              {"properties",
               {{"action",
                 {{"type", "string"},
                  {"enum", {"start", "stop", "status", "list", "drain"}},
                  {"description", "The command to execute"}}},
                {"data",
                 {{"type", "object"},
                  {"description", "Command-specific data payload"}}}}},
              {"additionalProperties", false}};
}

json ApiSchema::GetRequestExamples() {
  return json{
      {"start_session",
       {{"action", "start"},
        {"data",
         {{"app", "com.example.targetapp"},
          {"spawn", true},
          {"trace", json::array({{{"type", "java"},
                                  {"class", "android.media.MediaPlayer"},
                                  {"method", "start"}}})}}}}},
      {"stop_session", {{"action", "stop"}, {"data", {{"session", "12345"}}}}},
      {"get_status", {{"action", "status"}, {"data", {{"session", "12345"}}}}},
      {"list_sessions", {{"action", "list"}, {"data", json::object()}}},
      {"drain_messages",
       {{"action", "drain"}, {"data", {{"session", "12345"}}}}}};
}

Status ApiSchema::CheckFieldType(const json &value, json::value_t expected_type,
                                 const std::string &field_name) {
  if (value.type() != expected_type) {
    std::string expected_name;
    switch (expected_type) {
    case json::value_t::string:
      expected_name = "string";
      break;
    case json::value_t::number_integer:
      expected_name = "integer";
      break;
    case json::value_t::boolean:
      expected_name = "boolean";
      break;
    case json::value_t::array:
      expected_name = "array";
      break;
    case json::value_t::object:
      expected_name = "object";
      break;
    default:
      expected_name = "unknown";
    }

    return BadArgument("Field '" + field_name + "' must be of type " +
                       expected_name);
  }

  return Ok();
}

Status ApiSchema::ValidateTraceConfig(const json &trace_config) {
  if (!trace_config.is_array()) {
    return BadArgument("Field 'trace' must be an array");
  }

  for (size_t i = 0; i < trace_config.size(); ++i) {
    const auto &trace_item = trace_config[i];

    if (!trace_item.is_object()) {
      return BadArgument("Trace item " + std::to_string(i) +
                         " must be an object");
    }

    // Required: type field
    if (!trace_item.contains("type")) {
      return BadArgument("Trace item " + std::to_string(i) +
                         " missing 'type' field");
    }

    std::string type = trace_item["type"];
    if (type != "java" && type != "native") {
      return BadArgument("Trace item " + std::to_string(i) +
                         " has invalid type: " + type);
    }

    // Required: class or method fields
    if (type == "java") {
      if (!trace_item.contains("class")) {
        return BadArgument("Java trace item " + std::to_string(i) +
                           " missing 'class' field");
      }
    } else if (type == "native") {
      if (!trace_item.contains("class")) {
        return BadArgument("Native trace item " + std::to_string(i) +
                           " missing 'class' field");
      }
    }
  }

  return Ok();
}

} // namespace http