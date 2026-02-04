#pragma once

#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for draining cached script messages from a session.
 * Processes "drain" action requests to atomically retrieve and clear
 * buffered messages.
 */
class DrainMessagesHandler : public RequestHandler {
public:
  explicit DrainMessagesHandler(ApplicationDaemon *daemon);
  ~DrainMessagesHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  ApplicationDaemon *m_daemon;
};

} // namespace http
