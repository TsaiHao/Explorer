#pragma once

#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for session status commands.
 * Processes "status" action requests to query session or global daemon status.
 */
class StatusHandler : public RequestHandler {
public:
  explicit StatusHandler(ApplicationDaemon *daemon);
  ~StatusHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  /**
   * Validate status query specific requirements.
   * @param data The data section from the request
   * @return Status indicating validation result
   */
  Status ValidateStatusData(const json &data);

  /**
   * Extract session identifier (optional for global status).
   * @param data The request data
   * @return Session ID string if present, empty string for global status
   */
  std::string ExtractSessionId(const json &data);

  /**
   * Process the status query request.
   * @param session_id The session identifier (empty for global status)
   * @param res The HTTP response object
   */
  void ProcessStatusQuery(const std::string &session_id,
                          Poco::Net::HTTPServerResponse &res);

  ApplicationDaemon *m_daemon;
};

} // namespace http