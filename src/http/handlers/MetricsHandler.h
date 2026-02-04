#pragma once

#include "http/EnhancedRequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Metrics handler for comprehensive daemon monitoring.
 * Provides detailed performance metrics for monitoring and alerting systems.
 */
class MetricsHandler : public EnhancedRequestHandler {
public:
  explicit MetricsHandler(ApplicationDaemon *daemon);
  ~MetricsHandler() override = default;

protected:
  void ProcessRequest(Poco::Net::HTTPServerRequest &req,
                      Poco::Net::HTTPServerResponse &res,
                      utils::RequestContext &context) override;

private:
  /**
   * Collect comprehensive metrics.
   */
  nlohmann::json CollectMetrics();

  /**
   * Get daemon performance metrics.
   */
  nlohmann::json GetDaemonMetrics();

  /**
   * Get HTTP server metrics.
   */
  nlohmann::json GetHttpServerMetrics();

  /**
   * Get session management metrics.
   */
  nlohmann::json GetSessionMetrics();

  /**
   * Get state persistence metrics.
   */
  nlohmann::json GetStatePersistenceMetrics();

  /**
   * Get system performance metrics.
   */
  nlohmann::json GetSystemMetrics();

  /**
   * Get error and health metrics.
   */
  nlohmann::json GetErrorMetrics();

  ApplicationDaemon *m_daemon;
};

} // namespace http