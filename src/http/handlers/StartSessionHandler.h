#pragma once

#include "http/AsyncRequestHandler.h"
#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for session start commands.
 * Processes "start" action requests to create new instrumentation sessions.
 * Supports both synchronous and asynchronous session creation.
 */
class StartSessionHandler : public AsyncRequestHandler {
public:
  explicit StartSessionHandler(ApplicationDaemon *daemon);
  ~StartSessionHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  /**
   * Validate start session specific requirements.
   * @param data The data section from the request
   * @return Status indicating validation result
   */
  Status ValidateStartSessionData(const json &data);

  /**
   * Extract and validate target identification (app or pid).
   * @param data The request data
   * @return Status indicating validation result
   */
  Status ValidateTargetIdentification(const json &data);

  /**
   * Validate trace configuration if present.
   * @param trace_config The trace configuration array
   * @return Status indicating validation result
   */
  Status ValidateTraceConfiguration(const json &trace_config);

  /**
   * Process the session creation request.
   * @param session_config The validated session configuration
   * @param res The HTTP response object
   */
  void ProcessSessionCreation(const json &session_config,
                              Poco::Net::HTTPServerResponse &res);

  /**
   * Process the session creation request asynchronously.
   * @param session_config The validated session configuration
   * @param res The HTTP response object
   * @param timeout_sec Timeout in seconds (0 = use default)
   */
  void ProcessSessionCreationAsync(const json &session_config,
                                   Poco::Net::HTTPServerResponse &res,
                                   int timeout_sec = 0);

  ApplicationDaemon *m_daemon;
};

} // namespace http