#pragma once

#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for daemon statistics and state information.
 * Processes requests to get daemon stats and session history.
 */
class StatsHandler : public RequestHandler {
public:
  explicit StatsHandler(ApplicationDaemon *daemon);
  ~StatsHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  ApplicationDaemon *m_daemon;
};

} // namespace http