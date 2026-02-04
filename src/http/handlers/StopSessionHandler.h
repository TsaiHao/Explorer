#pragma once

#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for session stop commands.
 * Processes "stop" action requests to terminate existing instrumentation
 * sessions.
 */
class StopSessionHandler : public RequestHandler {
public:
  explicit StopSessionHandler(ApplicationDaemon *daemon);
  ~StopSessionHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  /**
   * Validate stop session specific requirements.
   * @param data The data section from the request
   * @return Status indicating validation result
   */
  Status ValidateStopSessionData(const json &data);

  /**
   * Extract and validate session identifier.
   * @param data The request data
   * @return Session ID string if valid, or error status
   */
  Result<std::string, Status> ExtractSessionId(const json &data);

  /**
   * Process the session termination request.
   * @param session_id The validated session identifier
   * @param res The HTTP response object
   */
  void ProcessSessionTermination(const std::string &session_id,
                                 Poco::Net::HTTPServerResponse &res);

  ApplicationDaemon *m_daemon;
};

} // namespace http