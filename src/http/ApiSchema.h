#pragma once

#include "nlohmann/json.hpp"
#include "utils/Result.h"
#include "utils/Status.h"

#include <string>
#include <vector>

namespace http {

using json = nlohmann::json;

/**
 * API command types supported by the daemon.
 */
enum class ApiCommand {
  kStart,  // Start a new session
  kStop,   // Stop an existing session
  kStatus, // Get session status
  kList,   // List all sessions
  kDrain   // Drain cached messages from a session
};

/**
 * JSON API schema definitions and validation utilities.
 */
class ApiSchema {
public:
  /**
   * Parse command type from action string.
   * @param action The action string from JSON request
   * @return ApiCommand enum or error if unknown
   */
  static Result<ApiCommand, Status> ParseCommand(const std::string &action);

  /**
   * Convert command enum to string.
   * @param command The command enum
   * @return String representation
   */
  static std::string CommandToString(ApiCommand command);

  /**
   * Validate a request JSON against the API schema.
   * @param request_json The JSON request to validate
   * @return Status indicating validation result
   */
  static Status ValidateRequest(const json &request_json);

  /**
   * Validate start session request data.
   * @param data The data section of the request
   * @return Status indicating validation result
   */
  static Status ValidateStartRequest(const json &data);

  /**
   * Validate stop session request data.
   * @param data The data section of the request
   * @return Status indicating validation result
   */
  static Status ValidateStopRequest(const json &data);

  /**
   * Validate status request data.
   * @param data The data section of the request
   * @return Status indicating validation result
   */
  static Status ValidateStatusRequest(const json &data);

  /**
   * Validate list request data (typically empty).
   * @param data The data section of the request
   * @return Status indicating validation result
   */
  static Status ValidateListRequest(const json &data);

  /**
   * Validate drain request data.
   * @param data The data section of the request
   * @return Status indicating validation result
   */
  static Status ValidateDrainRequest(const json &data);

  /**
   * Create a standard success response.
   * @param data The response data payload
   * @param message Optional success message
   * @return JSON response object
   */
  static json CreateSuccessResponse(const json &data = json::object(),
                                    const std::string &message = "");

  /**
   * Create a standard error response.
   * @param message The error message
   * @param error_code Optional error code
   * @param details Optional error details
   * @return JSON response object
   */
  static json CreateErrorResponse(const std::string &message,
                                  const std::string &error_code = "",
                                  const json &details = json::object());

  /**
   * Get the JSON schema for API requests (for documentation).
   * @return JSON schema object
   */
  static json GetRequestSchema();

  /**
   * Get example JSON requests for each command type.
   * @return JSON object with examples
   */
  static json GetRequestExamples();

private:
  /**
   * Check if a JSON value has the expected type.
   * @param value The JSON value to check
   * @param expected_type The expected JSON type
   * @param field_name The field name for error messages
   * @return Status indicating type check result
   */
  static Status CheckFieldType(const json &value, json::value_t expected_type,
                               const std::string &field_name);

  /**
   * Validate trace configuration array.
   * @param trace_config The trace configuration JSON
   * @return Status indicating validation result
   */
  static Status ValidateTraceConfig(const json &trace_config);
};

} // namespace http