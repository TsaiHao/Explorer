#pragma once

#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for unloading scripts from existing sessions.
 * Processes "unload_script" action requests to remove injected scripts.
 */
class UnloadScriptHandler : public RequestHandler {
public:
  explicit UnloadScriptHandler(ApplicationDaemon *daemon);
  ~UnloadScriptHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  ApplicationDaemon *m_daemon;
};

} // namespace http
