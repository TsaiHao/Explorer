#pragma once

#include "http/EnhancedRequestHandler.h"

// Forward declaration to avoid circular dependency
class ApplicationDaemon;

namespace http {

/**
 * Health check handler for daemon status monitoring.
 * Provides comprehensive health information for load balancers and monitoring
 * systems.
 */
class HealthHandler : public EnhancedRequestHandler {
public:
  explicit HealthHandler(ApplicationDaemon *daemon);
  ~HealthHandler() override = default;

protected:
  void ProcessRequest(Poco::Net::HTTPServerRequest &req,
                      Poco::Net::HTTPServerResponse &res,
                      utils::RequestContext &context) override;

private:
  /**
   * Perform comprehensive health checks.
   */
  nlohmann::json PerformHealthChecks();

  /**
   * Check FRIDA system status.
   */
  nlohmann::json CheckFridaHealth();

  /**
   * Check state manager health.
   */
  nlohmann::json CheckStateManagerHealth();

  /**
   * Check HTTP server health.
   */
  nlohmann::json CheckHttpServerHealth();

  /**
   * Check system resources.
   */
  nlohmann::json CheckSystemResources();

  ApplicationDaemon *m_daemon;
};

} // namespace http