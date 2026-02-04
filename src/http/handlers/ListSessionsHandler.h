#pragma once

#include "http/RequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Handler for session listing commands.
 * Processes "list" action requests to enumerate active sessions with optional
 * filtering.
 */
class ListSessionsHandler : public RequestHandler {
public:
  explicit ListSessionsHandler(ApplicationDaemon *daemon);
  ~ListSessionsHandler() override = default;

  void Handle(Poco::Net::HTTPServerRequest &req,
              Poco::Net::HTTPServerResponse &res) override;

private:
  /**
   * Validate list sessions specific requirements.
   * @param data The data section from the request
   * @return Status indicating validation result
   */
  Status ValidateListData(const json &data);

  /**
   * Extract and validate filter criteria.
   * @param data The request data
   * @return Filter object (empty if no filters specified)
   */
  json ExtractFilterCriteria(const json &data);

  /**
   * Validate filter object structure.
   * @param filter The filter criteria to validate
   * @return Status indicating validation result
   */
  Status ValidateFilterCriteria(const json &filter);

  /**
   * Process the session listing request.
   * @param filter The validated filter criteria
   * @param res The HTTP response object
   */
  void ProcessSessionListing(const json &filter,
                             Poco::Net::HTTPServerResponse &res);

  ApplicationDaemon *m_daemon;
};

} // namespace http