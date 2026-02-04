#include "EnhancedRequestHandler.h"
#include "utils/Log.h"

#include <algorithm>
#include <sstream>

namespace http {

EnhancedRequestHandler::EnhancedRequestHandler(const std::string &handler_name)
    : handler_name_(handler_name) {
  LOGI("Created enhanced request handler: {}", handler_name_);
}

void EnhancedRequestHandler::Handle(Poco::Net::HTTPServerRequest &req,
                                    Poco::Net::HTTPServerResponse &res) {
  auto start_time = std::chrono::steady_clock::now();

  // Generate request ID for tracking
  std::string request_id = utils::RequestIdGenerator::Generate();

  // Create request context
  utils::RequestContext context(request_id, req.getURI(), req.getMethod(),
                                GetClientIp(req));
  context.request_size = req.hasContentLength() ? req.getContentLength() : 0;

  // Increment request counter
  total_requests_.fetch_add(1);

  // Apply middleware
  RequestMiddleware::ApplyCorsHeaders(res);
  RequestMiddleware::ApplySecurityHeaders(res);
  RequestMiddleware::LogRequestStart(req, context);

  try {
    // Check rate limiting
    if (!CheckRateLimit(context.client_ip)) {
      utils::ErrorInfo rate_limit_error(
          utils::ErrorCode::kRateLimited, "Rate limit exceeded",
          "Too many requests from this IP address");
      rate_limit_error.request_id = request_id;
      SendError(res, rate_limit_error);
      return;
    }

    // Validate request format
    auto validation_error = ValidateRequest(req, context);
    if (validation_error.has_value()) {
      validation_error->request_id = request_id;
      SendError(res, *validation_error);
      return;
    }

    // Process the request
    ProcessRequest(req, res, context);

    // Update success counter if response is successful
    if (res.getStatus() >= 200 && res.getStatus() < 400) {
      successful_requests_.fetch_add(1);
    } else {
      failed_requests_.fetch_add(1);
    }

  } catch (const std::exception &e) {
    // Catch any unhandled exceptions
    failed_requests_.fetch_add(1);

    utils::ErrorInfo exception_error(
        utils::ErrorCode::kInternalError,
        "Unhandled exception during request processing", e.what());
    exception_error.request_id = request_id;
    SendError(res, exception_error);

    LOGE("Unhandled exception in {}: {}", handler_name_, e.what());
  }

  // Calculate and log request completion
  auto end_time = std::chrono::steady_clock::now();
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         end_time - start_time)
                         .count();
  total_processing_time_ms_.fetch_add(duration_ms);

  LogRequestCompletion(context, res.getStatus(), res.getContentLength());
}

void EnhancedRequestHandler::SendError(Poco::Net::HTTPServerResponse &res,
                                       const utils::ErrorInfo &error) {
  utils::ErrorHandler::SendErrorResponse(res, error);
  failed_requests_.fetch_add(1);
}

void EnhancedRequestHandler::SendError(Poco::Net::HTTPServerResponse &res,
                                       const Status &status,
                                       const std::string &request_id) {
  utils::ErrorHandler::SendErrorResponse(res, status, request_id);
  failed_requests_.fetch_add(1);
}

void EnhancedRequestHandler::SendSuccess(Poco::Net::HTTPServerResponse &res,
                                         const nlohmann::json &data,
                                         const std::string &message) {
  utils::ErrorHandler::SendSuccessResponse(res, data, message);
}

std::string
EnhancedRequestHandler::GetClientIp(Poco::Net::HTTPServerRequest &req) const {
  if (req.has("X-Forwarded-For")) {
    return req.get("X-Forwarded-For");
  }
  return req.clientAddress().toString();
}

void EnhancedRequestHandler::LogRequestCompletion(
    const utils::RequestContext &context, int response_status,
    size_t response_size) {
  nlohmann::json log_entry = {{"level", "INFO"},
                              {"type", "REQUEST_COMPLETED"},
                              {"handler", handler_name_},
                              {"request_id", context.request_id},
                              {"method", context.method},
                              {"endpoint", context.endpoint},
                              {"client_ip", context.client_ip},
                              {"status", response_status},
                              {"duration_ms", context.GetDurationMs()},
                              {"request_size", context.request_size},
                              {"response_size", response_size}};

  LOGI("REQUEST: {}", log_entry.dump());
}

bool EnhancedRequestHandler::CheckRateLimit(const std::string &client_ip) {
  std::lock_guard<std::mutex> lock(rate_limit_mutex_);

  auto now = std::chrono::steady_clock::now();
  auto &last_request = last_request_time_[client_ip];

  // Simple rate limiting: allow max one request per (1/kMaxRequestsPerSecond)
  // seconds
  auto min_interval = std::chrono::milliseconds(1000 / kMaxRequestsPerSecond);

  if (now - last_request < min_interval) {
    return false; // Rate limit exceeded
  }

  last_request = now;
  return true;
}

nlohmann::json EnhancedRequestHandler::GetMetrics() const {
  uint64_t total = total_requests_.load();
  uint64_t successful = successful_requests_.load();
  uint64_t failed = failed_requests_.load();
  uint64_t total_time = total_processing_time_ms_.load();

  double success_rate =
      total > 0 ? (static_cast<double>(successful) / total) * 100.0 : 0.0;
  double avg_response_time =
      total > 0 ? static_cast<double>(total_time) / total : 0.0;

  return nlohmann::json{{"handler_name", handler_name_},
                        {"total_requests", total},
                        {"successful_requests", successful},
                        {"failed_requests", failed},
                        {"success_rate_percent", success_rate},
                        {"average_response_time_ms", avg_response_time},
                        {"total_processing_time_ms", total_time}};
}

// RequestMiddleware implementation
void RequestMiddleware::ApplyCorsHeaders(Poco::Net::HTTPServerResponse &res) {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Headers",
          "Content-Type, Authorization, X-Requested-With");
  res.set("Access-Control-Max-Age", "86400");
}

void RequestMiddleware::ApplySecurityHeaders(
    Poco::Net::HTTPServerResponse &res) {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "DENY");
  res.set("X-XSS-Protection", "1; mode=block");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
}

void RequestMiddleware::LogRequestStart(Poco::Net::HTTPServerRequest &_,
                                        const utils::RequestContext &context) {
  LOGI("START REQUEST: {} {} from {} (Request ID: {})", context.method,
       context.endpoint, context.client_ip, context.request_id);
}

std::optional<utils::ErrorInfo>
RequestMiddleware::ValidateContentType(Poco::Net::HTTPServerRequest &req) {
  auto content_type = req.getContentType();

  // Allow requests without body
  if (req.getContentLength() == 0) {
    return std::nullopt;
  }

  // Check for JSON content type
  if (content_type.find("application/json") == std::string::npos) {
    return utils::ErrorInfo(
        utils::ErrorCode::kBadRequest, "Invalid content type",
        "Expected 'application/json' for POST requests with body");
  }

  return std::nullopt;
}

Result<nlohmann::json, utils::ErrorInfo>
RequestMiddleware::ParseJsonBody(Poco::Net::HTTPServerRequest &req) {
  if (req.getContentLength() == 0) {
    return Ok<nlohmann::json>(nlohmann::json::object());
  }

  try {
    std::istream &stream = req.stream();
    std::string body((std::istreambuf_iterator<char>(stream)),
                     std::istreambuf_iterator<char>());
    nlohmann::json parsed = nlohmann::json::parse(body);
    return Ok<nlohmann::json>(parsed);
  } catch (const nlohmann::json::parse_error &e) {
    return Err<utils::ErrorInfo>(
        utils::ErrorInfo(utils::ErrorCode::kInvalidJson,
                         "Invalid JSON in request body", e.what()));
  }
}

} // namespace http