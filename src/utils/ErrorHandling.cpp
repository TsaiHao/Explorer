#include "ErrorHandling.h"
#include "utils/Log.h"

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

namespace utils {

// Static member definitions
std::atomic<uint64_t> RequestIdGenerator::counter_{1};

std::unordered_map<StatusCode, ErrorCode> ErrorHandler::status_code_mapping_ = {
    {StatusCode::kOk, ErrorCode::kSuccess},
    {StatusCode::kBadArgument, ErrorCode::kBadRequest},
    {StatusCode::kNotFound, ErrorCode::kNotFound},
    {StatusCode::kPermissionDenied, ErrorCode::kForbidden},
    {StatusCode::kInvalidOperation, ErrorCode::kUnsupportedOperation},
    {StatusCode::kInvalidState, ErrorCode::kConflict},
    {StatusCode::kSdkFailure, ErrorCode::kInternalError},
    {StatusCode::kTimeout, ErrorCode::kTimeout},
};

std::unordered_map<ErrorCode, int> ErrorHandler::http_status_mapping_ = {
    {ErrorCode::kSuccess, 200},

    // Client errors (400-499)
    {ErrorCode::kBadRequest, 400},
    {ErrorCode::kInvalidJson, 400},
    {ErrorCode::kMissingField, 400},
    {ErrorCode::kInvalidFieldValue, 400},
    {ErrorCode::kInvalidSessionId, 400},
    {ErrorCode::kUnsupportedOperation, 400},

    {ErrorCode::kUnauthorized, 401},
    {ErrorCode::kForbidden, 403},

    {ErrorCode::kNotFound, 404},
    {ErrorCode::kSessionNotFound, 404},
    {ErrorCode::kResourceNotFound, 404},

    {ErrorCode::kTimeout, 408},
    {ErrorCode::kOperationTimeout, 408},
    {ErrorCode::kRequestTimeout, 408},

    {ErrorCode::kConflict, 409},
    {ErrorCode::kSessionAlreadyExists, 409},
    {ErrorCode::kDuplicateOperation, 409},

    {ErrorCode::kRateLimited, 429},

    // Server errors (500-599)
    {ErrorCode::kInternalError, 500},
    {ErrorCode::kDaemonNotInitialized, 500},
    {ErrorCode::kFridaError, 500},
    {ErrorCode::kStateManagerError, 500},

    {ErrorCode::kServiceUnavailable, 503},
    {ErrorCode::kDatabaseError, 503},
    {ErrorCode::kFileSystemError, 503},
    {ErrorCode::kNetworkError, 503},
    {ErrorCode::kResourceExhausted, 503},
};

// ErrorInfo implementation
nlohmann::json ErrorInfo::ToJson() const {
  nlohmann::json error_json = {
      {"error", true}, {"code", static_cast<int>(code)}, {"message", message}};

  if (!details.empty()) {
    error_json["details"] = details;
  }

  if (!field.empty()) {
    error_json["field"] = field;
  }

  if (!request_id.empty()) {
    error_json["request_id"] = request_id;
  }

  if (!context.empty()) {
    error_json["context"] = context;
  }

  return error_json;
}

int ErrorInfo::GetHttpStatusCode() const {
  return ErrorHandler::ErrorCodeToHttpStatus(code);
}

// ErrorHandler implementation
void ErrorHandler::SendErrorResponse(Poco::Net::HTTPServerResponse &res,
                                     const ErrorInfo &error) {
  int http_status = error.GetHttpStatusCode();
  nlohmann::json response_body = error.ToJson();
  std::string response_body_str = response_body.dump();

  res.setStatus(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(http_status));
  res.setContentType("application/json");
  res.setContentLength(response_body_str.length());

  std::ostream &out = res.send();
  out << response_body_str;

  // Log error for audit trail
  LogError(error);
}

void ErrorHandler::SendErrorResponse(Poco::Net::HTTPServerResponse &res,
                                     const Status &status,
                                     const std::string &request_id) {
  ErrorInfo error = StatusToErrorInfo(status);
  if (!request_id.empty()) {
    error.request_id = request_id;
  }

  SendErrorResponse(res, error);
}

ErrorInfo ErrorHandler::StatusToErrorInfo(const Status &status) {
  ErrorCode error_code = StatusCodeToErrorCode(status.Code());
  return ErrorInfo(error_code, status.Message().data());
}

ErrorCode ErrorHandler::StatusCodeToErrorCode(StatusCode status_code) {
  auto it = status_code_mapping_.find(status_code);
  if (it != status_code_mapping_.end()) {
    return it->second;
  }
  return ErrorCode::kInternalError;
}

int ErrorHandler::ErrorCodeToHttpStatus(ErrorCode error_code) {
  auto it = http_status_mapping_.find(error_code);
  if (it != http_status_mapping_.end()) {
    return it->second;
  }
  return 500; // Default to internal server error
}

void ErrorHandler::SendSuccessResponse(Poco::Net::HTTPServerResponse &res,
                                       const nlohmann::json &data,
                                       const std::string &message) {
  nlohmann::json response = {
      {"success", true}, {"message", message}, {"data", data}};

  std::string response_str = response.dump();
  res.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
  res.setContentType("application/json");
  res.setContentLength(response_str.length());

  std::ostream &out = res.send();
  out << response_str;
}

void ErrorHandler::LogError(const ErrorInfo &error, const std::string &endpoint,
                            const std::string &client_ip) {
  // Create structured log entry for error
  nlohmann::json log_entry = {
      {"level", "ERROR"},
      {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count()},
      {"error_code", static_cast<int>(error.code)},
      {"message", error.message},
      {"http_status", error.GetHttpStatusCode()}};

  if (!endpoint.empty()) {
    log_entry["endpoint"] = endpoint;
  }

  if (!client_ip.empty()) {
    log_entry["client_ip"] = client_ip;
  }

  if (!error.request_id.empty()) {
    log_entry["request_id"] = error.request_id;
  }

  if (!error.details.empty()) {
    log_entry["details"] = error.details;
  }

  if (!error.context.empty()) {
    log_entry["context"] = error.context;
  }

  // Log using structured logging
  LOGE("API_ERROR: {}", log_entry.dump());
}

// RequestContext implementation
double RequestContext::GetDurationMs() const {
  auto now = std::chrono::system_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::microseconds>(now - start_time);
  return duration.count() / 1000.0; // Convert to milliseconds
}

nlohmann::json RequestContext::ToJson() const {
  return nlohmann::json{{"request_id", request_id},
                        {"endpoint", endpoint},
                        {"method", method},
                        {"client_ip", client_ip},
                        {"duration_ms", GetDurationMs()},
                        {"request_size", request_size}};
}

// RequestIdGenerator implementation
std::string RequestIdGenerator::Generate() {
  // Generate a unique request ID using timestamp + counter + random component
  auto now = std::chrono::system_clock::now();
  auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch())
                       .count();

  uint64_t count = counter_.fetch_add(1);

  // Add some randomness
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> dis(1000, 9999);
  uint32_t random_part = dis(gen);

  std::ostringstream oss;
  oss << "req_" << std::hex << timestamp << "_" << count << "_" << random_part;
  return oss.str();
}

} // namespace utils