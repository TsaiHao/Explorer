#include "SessionDispatcherHandler.h"
#include "ApplicationDaemon.h"
#include "http/ApiSchema.h"
#include "utils/Log.h"

namespace http {

SessionDispatcherHandler::SessionDispatcherHandler(ApplicationDaemon *daemon) {
  // Create instances of all specialized handlers
  m_start_handler = std::make_shared<StartSessionHandler>(daemon);
  m_stop_handler = std::make_shared<StopSessionHandler>(daemon);
  m_status_handler = std::make_shared<StatusHandler>(daemon);
  m_list_handler = std::make_shared<ListSessionsHandler>(daemon);

  LOGI("SessionDispatcherHandler created with specialized handlers");
}

void SessionDispatcherHandler::Handle(Poco::Net::HTTPServerRequest &req,
                                      Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing request through session dispatcher");

  // Parse JSON request to determine action
  auto json_result = ParseRequestJson(req);
  if (json_result.IsErr()) {
    LOGE("Failed to parse JSON request: {}", json_result.UnwrapErr().Message());
    SendError(res, json_result.UnwrapErr());
    return;
  }

  auto request_json = json_result.Unwrap();

  // Basic validation - ensure we have an action field
  if (!request_json.contains("action")) {
    LOGE("Request missing required 'action' field");
    SendError(res, BadArgument("Missing required field: action"));
    return;
  }

  if (!request_json["action"].is_string()) {
    LOGE("Request 'action' field is not a string");
    SendError(res, BadArgument("Field 'action' must be a string"));
    return;
  }

  std::string action = request_json["action"];
  LOGI("Dispatching request with action: {}", action);

  // Route to appropriate handler based on action
  if (action == "start") {
    m_start_handler->Handle(req, res);
  } else if (action == "stop") {
    m_stop_handler->Handle(req, res);
  } else if (action == "status") {
    m_status_handler->Handle(req, res);
  } else if (action == "list") {
    m_list_handler->Handle(req, res);
  } else {
    LOGE("Unknown action: {}", action);
    SendError(res,
              BadArgument("Unknown action: " + action +
                          ". Supported actions: start, stop, status, list"));
  }
}

} // namespace http