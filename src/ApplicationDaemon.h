#pragma once

#include "http/ApiSchema.h"
#include "http/HttpServer.h"
#include "nlohmann/json.hpp"
#include "utils/Macros.h"
#include "utils/StateManager.h"
#include "utils/Status.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

using json = nlohmann::json;

/**
 * Daemon-mode Application class.
 * Runs persistently in the background, managing sessions via HTTP API.
 */
class ApplicationDaemon {
public:
  explicit ApplicationDaemon(const std::vector<std::string_view> &args);
  ~ApplicationDaemon();

  DISABLE_COPY_AND_MOVE(ApplicationDaemon);

  /**
   * Initialize the daemon and prepare for operation.
   * @return Status indicating initialization success/failure
   */
  Status Initialize();

  /**
   * Start the daemon - runs indefinitely until shutdown.
   * Starts HTTP server and enters main event loop.
   * @return Status indicating final shutdown status
   */
  Status Run();

  /**
   * Shutdown the daemon gracefully.
   */
  void Shutdown();

  /**
   * Check if daemon is currently running.
   * @return True if daemon is active
   */
  bool IsRunning() const;

  // Session management API methods
  /**
   * Start a new instrumentation session.
   * @param config JSON configuration for the session
   * @return Status and session data if successful
   */
  Result<json, Status> StartSession(const json &config);

  /**
   * Start a new instrumentation session with cancellation support.
   * @param config JSON configuration for the session
   * @param should_cancel Function that returns true if operation should be
   * cancelled
   * @return Status and session data if successful
   */
  Result<json, Status>
  StartSessionWithCancellation(const json &config,
                               std::function<bool()> should_cancel);

  /**
   * Stop an existing session.
   * @param session_id The session ID to stop
   * @return Status indicating success/failure
   */
  Status StopSession(const std::string &session_id);

  /**
   * Get status of a specific session or global status.
   * @param session_id Optional session ID (empty for global status)
   * @return Status and session/global status data
   */
  Result<json, Status> GetSessionStatus(const std::string &session_id = "");

  /**
   * List all active sessions.
   * @param filter Optional filter criteria
   * @return Status and list of sessions
   */
  Result<json, Status> ListSessions(const json &filter = json::object());

  /**
   * Drain cached messages from a session.
   * @param session_id The session ID (PID as string) to drain messages from
   * @return Status and drained messages data
   */
  Result<json, Status> DrainSessionMessages(const std::string &session_id);

  /**
   * Get daemon statistics and state information.
   * @return Status and daemon statistics
   */
  Result<json, Status> GetDaemonStats();

  /**
   * Get session history.
   * @param limit Maximum number of historical sessions to return
   * @return Status and session history
   */
  Result<json, Status> GetSessionHistory(size_t limit = 100);

  /**
   * Perform state recovery operations.
   * Called automatically on daemon startup to recover from unexpected
   * shutdowns.
   * @return Status and number of sessions recovered
   */
  Result<size_t, Status> RecoverState();

public: // Temporarily public for SessionHandler access
  class Impl;

private:
  std::unique_ptr<Impl> m_impl;
};