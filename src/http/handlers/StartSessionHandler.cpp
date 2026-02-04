#include "StartSessionHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

StartSessionHandler::StartSessionHandler(ApplicationDaemon *daemon)
    : AsyncRequestHandler(
          60), // 60 second default timeout for session operations
      m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("StartSessionHandler created with null ApplicationDaemon pointer");
  }
}

void StartSessionHandler::Handle(Poco::Net::HTTPServerRequest &req,
                                 Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing start session request");

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

  // Ensure this is a start command
  std::string action = request_json["action"];
  if (action != "start") {
    LOGE("StartSessionHandler received non-start action: {}", action);
    SendError(res, 400, "Handler mismatch: expected 'start' action");
    return;
  }

  const json &data = request_json["data"];

  // Perform start-session specific validation
  auto start_validation = ValidateStartSessionData(data);
  if (!start_validation.Ok()) {
    LOGE("Start session validation failed: {}", start_validation.Message());
    SendError(res, start_validation);
    return;
  }

  // Check if async processing is requested
  bool use_async = false;
  int timeout_sec = 60; // Default timeout for async operations

  if (data.contains("async") && data["async"].is_boolean()) {
    use_async = data["async"];
  }

  if (data.contains("timeout") && data["timeout"].is_number()) {
    timeout_sec = data["timeout"];
    if (timeout_sec <= 0 || timeout_sec > 300) { // Max 5 minutes
      SendError(res, BadArgument("timeout must be between 1 and 300 seconds"));
      return;
    }
  }

  // Process the session creation (async or sync)
  if (use_async) {
    ProcessSessionCreationAsync(data, res, timeout_sec);
  } else {
    ProcessSessionCreation(data, res);
  }
}

Status StartSessionHandler::ValidateStartSessionData(const json &data) {
  // Validate target identification
  auto target_status = ValidateTargetIdentification(data);
  if (!target_status.Ok()) {
    return target_status;
  }

  // Validate trace configuration if present
  if (data.contains("trace")) {
    auto trace_status = ValidateTraceConfiguration(data["trace"]);
    if (!trace_status.Ok()) {
      return trace_status;
    }
  }

  // Validate SSL dumper configuration if present
  if (data.contains("ssl_dumper")) {
    if (!data["ssl_dumper"].is_object()) {
      return BadArgument("ssl_dumper must be an object");
    }

    const json &ssl_config = data["ssl_dumper"];
    if (ssl_config.contains("output")) {
      if (!ssl_config["output"].is_string()) {
        return BadArgument("ssl_dumper.output must be a string");
      }

      std::string output_path = ssl_config["output"];
      if (output_path.empty()) {
        return BadArgument("ssl_dumper.output path cannot be empty");
      }
    }
  }

  // Validate scripts array if present
  if (data.contains("scripts")) {
    if (!data["scripts"].is_array()) {
      return BadArgument("scripts must be an array");
    }

    for (const auto &script : data["scripts"]) {
      if (!script.is_string()) {
        return BadArgument("All script paths must be strings");
      }

      std::string script_path = script;
      if (script_path.empty()) {
        return BadArgument("Script path cannot be empty");
      }
    }
  }

  // Validate inline script source if present
  if (data.contains("script_source")) {
    if (!data["script_source"].is_string()) {
      return BadArgument("script_source must be a string");
    }
  }

  return Ok();
}

Status StartSessionHandler::ValidateTargetIdentification(const json &data) {
  bool has_app = data.contains("app") && !data["app"].is_null();
  bool has_pid = data.contains("pid") && !data["pid"].is_null();
  bool has_am_start = data.contains("am_start") && !data["am_start"].is_null();

  // Must have at least one target identification method
  if (!has_app && !has_pid && !has_am_start) {
    return BadArgument(
        "Must specify at least one of: 'app', 'pid', or 'am_start'");
  }

  // Validate app field if present
  if (has_app) {
    if (!data["app"].is_string()) {
      return BadArgument("'app' field must be a string");
    }

    std::string app_name = data["app"];
    if (app_name.empty()) {
      return BadArgument("'app' field cannot be empty");
    }

    // Basic package name validation (Android package naming)
    if (app_name.find('.') == std::string::npos) {
      LOGW("App name '{}' doesn't appear to be a valid Android package name",
           app_name);
    }
  }

  // Validate pid field if present
  if (has_pid) {
    if (!data["pid"].is_number_integer()) {
      return BadArgument("'pid' field must be an integer");
    }

    int pid = data["pid"];
    if (pid <= 0) {
      return BadArgument("'pid' must be a positive integer");
    }
  }

  // Validate am_start field if present
  if (has_am_start) {
    if (!data["am_start"].is_string()) {
      return BadArgument("'am_start' field must be a string");
    }

    std::string am_command = data["am_start"];
    if (am_command.empty()) {
      return BadArgument("'am_start' field cannot be empty");
    }

    // Basic validation that it contains activity specification
    if (am_command.find('/') == std::string::npos) {
      return BadArgument("'am_start' should contain activity specification "
                         "(package/activity)");
    }
  }

  // Validate spawn flag if present
  if (data.contains("spawn") && !data["spawn"].is_boolean()) {
    return BadArgument("'spawn' field must be a boolean");
  }

  return Ok();
}

Status
StartSessionHandler::ValidateTraceConfiguration(const json &trace_config) {
  if (!trace_config.is_array()) {
    return BadArgument("'trace' must be an array");
  }

  if (trace_config.empty()) {
    return BadArgument("'trace' array cannot be empty");
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
                         " missing required 'type' field");
    }

    if (!trace_item["type"].is_string()) {
      return BadArgument("Trace item " + std::to_string(i) +
                         " 'type' must be a string");
    }

    std::string type = trace_item["type"];
    if (type != "java" && type != "native") {
      return BadArgument("Trace item " + std::to_string(i) +
                         " has invalid type: '" + type +
                         "' (must be 'java' or 'native')");
    }

    // Required: class field
    if (!trace_item.contains("class")) {
      return BadArgument("Trace item " + std::to_string(i) +
                         " missing required 'class' field");
    }

    if (!trace_item["class"].is_string()) {
      return BadArgument("Trace item " + std::to_string(i) +
                         " 'class' must be a string");
    }

    std::string class_name = trace_item["class"];
    if (class_name.empty()) {
      return BadArgument("Trace item " + std::to_string(i) +
                         " 'class' cannot be empty");
    }

    // Optional but recommended: method field
    if (trace_item.contains("method")) {
      if (!trace_item["method"].is_string()) {
        return BadArgument("Trace item " + std::to_string(i) +
                           " 'method' must be a string");
      }
    }

    // Optional: namespace field (for native traces)
    if (trace_item.contains("namespace")) {
      if (!trace_item["namespace"].is_string()) {
        return BadArgument("Trace item " + std::to_string(i) +
                           " 'namespace' must be a string");
      }
    }

    // Optional boolean flags
    for (const auto &flag : {"arguments", "log", "backtrace", "atrace"}) {
      if (trace_item.contains(flag) && !trace_item[flag].is_boolean()) {
        return BadArgument("Trace item " + std::to_string(i) + " '" + flag +
                           "' must be a boolean");
      }
    }

    // Optional: dump field (SQLite output path)
    if (trace_item.contains("dump")) {
      if (!trace_item["dump"].is_string()) {
        return BadArgument("Trace item " + std::to_string(i) +
                           " 'dump' must be a string");
      }

      std::string dump_path = trace_item["dump"];
      if (dump_path.empty()) {
        return BadArgument("Trace item " + std::to_string(i) +
                           " 'dump' path cannot be empty");
      }
    }

    // Optional: transform array
    if (trace_item.contains("transform")) {
      if (!trace_item["transform"].is_array()) {
        return BadArgument("Trace item " + std::to_string(i) +
                           " 'transform' must be an array");
      }

      for (size_t j = 0; j < trace_item["transform"].size(); ++j) {
        const auto &transform = trace_item["transform"][j];
        if (!transform.is_object()) {
          return BadArgument("Trace item " + std::to_string(i) + " transform " +
                             std::to_string(j) + " must be an object");
        }

        if (!transform.contains("index") ||
            !transform["index"].is_number_integer()) {
          return BadArgument("Trace item " + std::to_string(i) + " transform " +
                             std::to_string(j) + " missing 'index' field");
        }

        if (!transform.contains("new_value")) {
          return BadArgument("Trace item " + std::to_string(i) + " transform " +
                             std::to_string(j) + " missing 'new_value' field");
        }
      }
    }
  }

  return Ok();
}

void StartSessionHandler::ProcessSessionCreation(
    const json &session_config, Poco::Net::HTTPServerResponse &res) {
  LOGI("Creating session with config: {}", session_config.dump());

  if (m_daemon == nullptr) {
    LOGE("Cannot process session creation - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Call the daemon's StartSession method
  auto result = m_daemon->StartSession(session_config);

  if (result.IsErr()) {
    LOGE("Session creation failed: {}", result.UnwrapErr().Message());
    SendError(res, result.UnwrapErr());
    return;
  }

  // Success! Return the session data
  json session_data = result.Unwrap();

  try {
    LOGI("Session data type: {}", session_data.type_name());
    LOGI("Session data size: {}", session_data.size());

    // Try to dump individual fields to find the problematic one
    for (const auto& [key, value] : session_data.items()) {
      try {
        LOGI("Field '{}': type={}, value={}", key, value.type_name(), value.dump());
      } catch (const json::exception& e) {
        LOGE("JSON error in field '{}': {}", key, e.what());
      }
    }

    LOGI("Full session data dump: {}", session_data.dump());
  } catch (const json::exception& e) {
    LOGE("JSON error in session_data.dump(): {}", e.what());
  }

  try {
    SendSuccess(res, session_data, "Session started successfully");
  } catch (const json::exception& e) {
    LOGE("JSON error in SendSuccess(): {}", e.what());
    SendError(res, 500, std::string("JSON serialization error: ") + e.what());
  }
}

void StartSessionHandler::ProcessSessionCreationAsync(
    const json &session_config, Poco::Net::HTTPServerResponse &res,
    int timeout_sec) {
  LOGI("Creating session asynchronously with config: {}",
       session_config.dump());

  if (m_daemon == nullptr) {
    LOGE("Cannot process async session creation - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Create an async operation that uses the cancellation-aware Device method
  auto async_operation = [this, session_config]() -> Result<json, Status> {
    // Use the cancellation-aware method from ApplicationDaemon
    auto result = m_daemon->StartSessionWithCancellation(
        session_config, [this]() { return ShouldCancel(); });

    // Periodically check for cancellation during the operation
    if (ShouldCancel()) {
      // If cancelled, try to stop any session we may have created
      if (result.IsOk()) {
        try {
          auto session_data = result.Unwrap();
          std::string session_id = session_data["session_id"];
          m_daemon->StopSession(session_id);
          LOGW("Cleaned up session {} after async cancellation", session_id);
        } catch (const std::exception &e) {
          LOGE("Failed to clean up cancelled async session: {}", e.what());
        }
      }
      return Err<Status>(Timeout("Async session creation was cancelled"));
    }

    return result;
  };

  // Execute the operation asynchronously
  ExecuteAsync<json>(async_operation, res, timeout_sec);
}

} // namespace http