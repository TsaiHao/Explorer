#pragma once

#include "Poco/Net/HTTPServerResponse.h"
#include "nlohmann/json.hpp"
#include "utils/Status.h"

#include <string>
#include <unordered_map>

namespace utils {

/**
 * Structured error codes for comprehensive error handling.
 */
enum class ErrorCode {
  // Success
  kSuccess = 0,

  // Client errors (400-499)
  kBadRequest = 4000,
  kInvalidJson = 4001,
  kMissingField = 4002,
  kInvalidFieldValue = 4003,
  kInvalidSessionId = 4004,
  kUnsupportedOperation = 4005,

  // Authentication/Authorization (401-403)
  kUnauthorized = 4010,
  kForbidden = 4030,
  kRateLimited = 4290,

  // Not Found (404)
  kNotFound = 4040,
  kSessionNotFound = 4041,
  kResourceNotFound = 4042,

  // Conflict (409)
  kConflict = 4090,
  kSessionAlreadyExists = 4091,
  kDuplicateOperation = 4092,

  // Request Timeout (408)
  kTimeout = 4080,
  kOperationTimeout = 4081,
  kRequestTimeout = 4082,

  // Server errors (500-599)
  kInternalError = 5000,
  kServiceUnavailable = 5030,
  kDaemonNotInitialized = 5031,
  kFridaError = 5032,
  kStateManagerError = 5033,

  // Infrastructure errors
  kDatabaseError = 5100,
  kFileSystemError = 5101,
  kNetworkError = 5102,
  kResourceExhausted = 5103,
};

/**
 * Enhanced error information with structured details.
 */
struct ErrorInfo {
  ErrorCode code;
  std::string message;
  std::string details;
  std::string field;      // Field name for validation errors
  std::string request_id; // Request ID for tracking
  nlohmann::json context; // Additional context information

  ErrorInfo(ErrorCode c, const std::string &msg, const std::string &det = "")
      : code(c), message(msg), details(det) {}

  // Convert to JSON for API responses
  nlohmann::json ToJson() const;

  // Get appropriate HTTP status code
  int GetHttpStatusCode() const;
};

/**
 * Error handling utilities for HTTP API responses.
 */
class ErrorHandler {
public:
  /**
   * Send a structured error response.
   */
  static void SendErrorResponse(Poco::Net::HTTPServerResponse &res,
                                const ErrorInfo &error);

  /**
   * Send a structured error response from Status.
   */
  static void SendErrorResponse(Poco::Net::HTTPServerResponse &res,
                                const Status &status,
                                const std::string &request_id = "");

  /**
   * Convert Status to ErrorInfo.
   */
  static ErrorInfo StatusToErrorInfo(const Status &status);

  /**
   * Get error code from StatusCode.
   */
  static ErrorCode StatusCodeToErrorCode(StatusCode status_code);

  /**
   * Get HTTP status code from ErrorCode.
   */
  static int ErrorCodeToHttpStatus(ErrorCode error_code);

  /**
   * Create a success response.
   */
  static void
  SendSuccessResponse(Poco::Net::HTTPServerResponse &res,
                      const nlohmann::json &data = nlohmann::json::object(),
                      const std::string &message = "Success");

  /**
   * Log error for audit trail.
   */
  static void LogError(const ErrorInfo &error, const std::string &endpoint = "",
                       const std::string &client_ip = "");

private:
  static std::unordered_map<StatusCode, ErrorCode> status_code_mapping_;
  static std::unordered_map<ErrorCode, int> http_status_mapping_;
};

/**
 * Request context for error tracking and logging.
 */
struct RequestContext {
  std::string request_id;
  std::string endpoint;
  std::string method;
  std::string client_ip;
  std::chrono::system_clock::time_point start_time;
  size_t request_size;

  RequestContext(const std::string &req_id, const std::string &ep,
                 const std::string &meth, const std::string &ip = "")
      : request_id(req_id), endpoint(ep), method(meth), client_ip(ip),
        start_time(std::chrono::system_clock::now()), request_size(0) {}

  // Get request duration in milliseconds
  double GetDurationMs() const;

  // Convert to JSON for logging
  nlohmann::json ToJson() const;
};

/**
 * Request ID generation for tracking.
 */
class RequestIdGenerator {
public:
  static std::string Generate();

private:
  static std::atomic<uint64_t> counter_;
};

} // namespace utils