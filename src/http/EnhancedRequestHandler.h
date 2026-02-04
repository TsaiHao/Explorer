#pragma once

#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "RequestHandler.h"
#include "utils/ErrorHandling.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_map>

namespace http {

/**
 * Enhanced request handler with comprehensive error handling, monitoring, and
 * logging.
 */
class EnhancedRequestHandler : public RequestHandler {
public:
  explicit EnhancedRequestHandler(const std::string &handler_name);
  virtual ~EnhancedRequestHandler() = default;

  /**
   * Main request handling with full monitoring and error handling.
   */
  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

protected:
  /**
   * Actual request processing to be implemented by subclasses.
   * @param req HTTP request
   * @param res HTTP response
   * @param context Request context for logging and tracking
   */
  virtual void ProcessRequest(Poco::Net::HTTPServerRequest &req,
                              Poco::Net::HTTPServerResponse &res,
                              utils::RequestContext &context) = 0;

  /**
   * Validate request before processing.
   * @param req HTTP request
   * @param context Request context
   * @return ErrorInfo if validation fails, std::nullopt if valid
   */
  virtual std::optional<utils::ErrorInfo>
  ValidateRequest(Poco::Net::HTTPServerRequest &req,
                  utils::RequestContext &context) {
    (void)req;
    (void)context;
    return std::nullopt;
  }

  /**
   * Send structured error response with full logging.
   */
  void SendError(Poco::Net::HTTPServerResponse &res,
                 const utils::ErrorInfo &error);

  /**
   * Send structured error response from Status.
   */
  void SendError(Poco::Net::HTTPServerResponse &res, const Status &status,
                 const std::string &request_id = "");

  /**
   * Send structured success response.
   */
  void SendSuccess(Poco::Net::HTTPServerResponse &res,
                   const nlohmann::json &data = nlohmann::json::object(),
                   const std::string &message = "Success");

  /**
   * Get client IP address from request.
   */
  std::string GetClientIp(Poco::Net::HTTPServerRequest &req) const;

  /**
   * Log request completion for audit trail.
   */
  void LogRequestCompletion(const utils::RequestContext &context,
                            int response_status, size_t response_size = 0);

private:
  std::string handler_name_;

  // Request metrics
  mutable std::atomic<uint64_t> total_requests_{0};
  mutable std::atomic<uint64_t> successful_requests_{0};
  mutable std::atomic<uint64_t> failed_requests_{0};
  mutable std::atomic<uint64_t> total_processing_time_ms_{0};

  // Rate limiting (simple implementation)
  mutable std::mutex rate_limit_mutex_;
  mutable std::unordered_map<std::string, std::chrono::steady_clock::time_point>
      last_request_time_;
  static constexpr int kMaxRequestsPerSecond = 100;

  /**
   * Check rate limiting for client.
   */
  bool CheckRateLimit(const std::string &client_ip);

public:
  /**
   * Get handler metrics for monitoring.
   */
  nlohmann::json GetMetrics() const;
};

/**
 * Middleware for common request processing (CORS, logging, etc.).
 */
class RequestMiddleware {
public:
  /**
   * Apply CORS headers.
   */
  static void ApplyCorsHeaders(Poco::Net::HTTPServerResponse &res);

  /**
   * Apply security headers.
   */
  static void ApplySecurityHeaders(Poco::Net::HTTPServerResponse &res);

  /**
   * Log request start.
   */
  static void LogRequestStart(Poco::Net::HTTPServerRequest &req,
                              const utils::RequestContext &context);

  /**
   * Validate content type for POST requests.
   */
  static std::optional<utils::ErrorInfo>
  ValidateContentType(Poco::Net::HTTPServerRequest &req);

  /**
   * Parse and validate JSON request body.
   */
  static Result<nlohmann::json, utils::ErrorInfo>
  ParseJsonBody(Poco::Net::HTTPServerRequest &req);
};

} // namespace http