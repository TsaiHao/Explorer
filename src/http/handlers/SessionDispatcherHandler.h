#pragma once

#include "http/RequestHandler.h"
#include "http/handlers/ListSessionsHandler.h"
#include "http/handlers/StartSessionHandler.h"
#include "http/handlers/StatusHandler.h"
#include "http/handlers/StopSessionHandler.h"

#include <memory>

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Dispatcher handler for the generic /api/v1/session endpoint.
 * Parses the action field and routes to appropriate specialized handlers.
 * Provides backward compatibility with the original API design.
 */
class SessionDispatcherHandler : public RequestHandler {
public:
  explicit SessionDispatcherHandler(ApplicationDaemon *daemon);
  ~SessionDispatcherHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  // Specialized handlers
  std::shared_ptr<StartSessionHandler> m_start_handler;
  std::shared_ptr<StopSessionHandler> m_stop_handler;
  std::shared_ptr<StatusHandler> m_status_handler;
  std::shared_ptr<ListSessionsHandler> m_list_handler;
};

} // namespace http