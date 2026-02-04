#pragma once

#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "nlohmann/json.hpp"
#include "utils/Result.h"
#include "utils/Status.h"

#include <string>

namespace http {

using json = nlohmann::json;

/**
 * Base class for HTTP request handlers.
 * Provides common functionality for parsing requests and formatting responses.
 */
class RequestHandler : public Poco::Net::HTTPRequestHandler {
public:
  virtual ~RequestHandler() = default;

  /**
   * Handle an HTTP request and generate a response.
   * This is the Poco::Net interface method.
   * @param request The HTTP request
   * @param response The HTTP response to populate
   */
  void handleRequest(Poco::Net::HTTPServerRequest &request,
                     Poco::Net::HTTPServerResponse &response) override;

protected:
  /**
   * Handle an HTTP request and generate a response.
   * Subclasses should implement this method instead of handleRequest.
   * @param req The HTTP request
   * @param res The HTTP response to populate
   */
  virtual void Handle(Poco::Net::HTTPServerRequest &req,
                      Poco::Net::HTTPServerResponse &res) = 0;

protected:
  /**
   * Parse JSON from request body.
   * @param req The HTTP request
   * @return Parsed JSON or error
   */
  Result<json, Status> ParseRequestJson(Poco::Net::HTTPServerRequest &req);

  /**
   * Send a JSON success response.
   * @param res The HTTP response
   * @param data Optional data payload
   * @param message Optional success message
   */
  void SendSuccess(Poco::Net::HTTPServerResponse &res,
                   const json &data = json::object(),
                   const std::string &message = "");

  /**
   * Send a JSON error response.
   * @param res The HTTP response
   * @param status_code HTTP status code
   * @param message Error message
   * @param details Optional error details
   */
  void SendError(Poco::Net::HTTPServerResponse &res, int status_code,
                 const std::string &message,
                 const json &details = json::object());

  /**
   * Send a JSON error response from a Status object.
   * @param res The HTTP response
   * @param status The status containing error information
   */
  void SendError(Poco::Net::HTTPServerResponse &res, const Status &status);

  /**
   * Validate required fields in JSON request.
   * @param request_json The JSON to validate
   * @param required_fields List of required field names
   * @return Status indicating validation result
   */
  Status
  ValidateRequiredFields(const json &request_json,
                         const std::vector<std::string> &required_fields);

private:
  /**
   * Convert Status error code to HTTP status code.
   * @param status_code The internal status code
   * @return Corresponding HTTP status code
   */
  int StatusToHttpCode(StatusCode status_code);
};

} // namespace http