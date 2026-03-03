#pragma once

#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for loading scripts into existing sessions.
 * Processes "load_script" action requests to dynamically inject scripts.
 */
class LoadScriptHandler : public RequestHandler {
public:
  explicit LoadScriptHandler(ApplicationDaemon *daemon);
  ~LoadScriptHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  ApplicationDaemon *m_daemon;
};

} // namespace http
