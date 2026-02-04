#include "RequestHandler.h"
#include "utils/Log.h"

#include "Poco/StreamCopier.h"
#include "utils/Status.h"

#include <sstream>

namespace http {

void RequestHandler::handleRequest(Poco::Net::HTTPServerRequest &request,
                                   Poco::Net::HTTPServerResponse &response) {
  try {
    Handle(request, response);
  } catch (const std::exception &e) {
    LOGE("Exception in request handler: {}", e.what());
    SendError(response, 500, "Internal server error");
  }
}

Result<json, Status>
RequestHandler::ParseRequestJson(Poco::Net::HTTPServerRequest &req) {
  std::istream &stream = req.stream();
  std::string body;

  if (req.hasContentLength()) {
    body.reserve(req.getContentLength());
  }

  Poco::StreamCopier::copyToString(stream, body);

  if (body.empty()) {
    return Err(BadArgument("Empty request body"));
  }

  try {
    return Ok(json::parse(body));
  } catch (const json::parse_error &e) {
    LOGE("JSON parse error: {}", e.what());
    return Err(Status(StatusCode::kBadArgument,
                      std::string("Invalid JSON: ") + e.what()));
  }
}

void RequestHandler::SendSuccess(Poco::Net::HTTPServerResponse &res,
                                 const json &data, const std::string &message) {
  try {
    LOGI("SendSuccess: Building response with data type: {}", data.type_name());

    json response = {{"status", "success"}, {"data", data}};

    if (!message.empty()) {
      response["message"] = message;
    }

    LOGI("SendSuccess: Response structure built successfully");

    std::string response_body;
    try {
      response_body = response.dump(2);
      LOGI("SendSuccess: JSON dump successful, body length: {}", response_body.length());
    } catch (const json::exception& e) {
      LOGE("SendSuccess: JSON dump failed: {}", e.what());
      throw;
    }

    res.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    res.setContentType("application/json");
    res.setContentLength(response_body.length());

    std::ostream &out = res.send();
    out << response_body;

    LOGI("SendSuccess: Response sent successfully");
  } catch (const json::exception& e) {
    LOGE("SendSuccess: JSON exception: {}", e.what());
    throw;
  }
}

void RequestHandler::SendError(Poco::Net::HTTPServerResponse &res,
                               int status_code, const std::string &message,
                               const json &details) {
  json response = {{"status", "error"}, {"message", message}};

  if (!details.empty()) {
    response["details"] = details;
  }

  std::string response_body = response.dump(2);

  res.setStatus(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(status_code));
  res.setContentType("application/json");
  res.setContentLength(response_body.length());

  std::ostream &out = res.send();
  out << response_body;
}

void RequestHandler::SendError(Poco::Net::HTTPServerResponse &res,
                               const Status &status) {
  int http_code = StatusToHttpCode(status.Code());
  json details = {{"code", static_cast<int>(status.Code())}};
  SendError(res, http_code, std::string(status.Message()), details);
}

Status RequestHandler::ValidateRequiredFields(
    const json &request_json, const std::vector<std::string> &required_fields) {
  for (const auto &field : required_fields) {
    if (!request_json.contains(field)) {
      return Status(StatusCode::kBadArgument,
                    std::string("Missing required field: ") + field);
    }
  }
  return Ok();
}

int RequestHandler::StatusToHttpCode(StatusCode status_code) {
  switch (status_code) {
  case StatusCode::kOk:
    return 200;
  case StatusCode::kBadArgument:
    return 400;
  case StatusCode::kPermissionDenied:
    return 403;
  case StatusCode::kNotFound:
    return 404;
  case StatusCode::kTimeout:
    return 408;
  case StatusCode::kInvalidOperation:
  case StatusCode::kInvalidState:
    return 409;
  case StatusCode::kSdkFailure:
  default:
    return 500;
  }
}

} // namespace http