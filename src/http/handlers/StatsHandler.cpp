#include "StatsHandler.h"
#include "ApplicationDaemon.h"
#include "utils/Log.h"

#include "Poco/URI.h"

namespace http {

StatsHandler::StatsHandler(ApplicationDaemon *daemon) : m_daemon(daemon) {
  if (m_daemon == nullptr) {
    LOGE("StatsHandler created with null ApplicationDaemon pointer");
  }
}

void StatsHandler::Handle(Poco::Net::HTTPServerRequest &req,
                          Poco::Net::HTTPServerResponse &res) {
  LOGI("Processing stats request");

  if (m_daemon == nullptr) {
    LOGE("Cannot process stats request - daemon is null");
    SendError(res, 500, "Internal server error: daemon not available");
    return;
  }

  // Check if this is a request for session history
  Poco::URI uri(req.getURI());
  auto params = uri.getQueryParameters();

  std::string history_param;
  std::string limit_param;

  for (const auto &param : params) {
    if (param.first == "history") {
      history_param = param.second;
    } else if (param.first == "limit") {
      limit_param = param.second;
    }
  }

  if (!history_param.empty()) {
    size_t limit = 100; // Default limit

    // Parse limit parameter if provided
    if (!limit_param.empty()) {
      try {
        limit = std::stoull(limit_param);
        if (limit > 1000) {
          limit = 1000; // Cap at 1000 for performance
        }
      } catch (const std::exception &e) {
        SendError(res, 400, "Invalid limit parameter");
        return;
      }
    }

    // Get session history
    auto history_result = m_daemon->GetSessionHistory(limit);
    if (history_result.IsErr()) {
      LOGE("Failed to get session history: {}",
           history_result.UnwrapErr().Message());
      SendError(res, history_result.UnwrapErr());
      return;
    }

    json history_data = history_result.Unwrap();
    SendSuccess(res, history_data, "Session history retrieved successfully");
    return;
  }

  // Default: return daemon statistics
  auto stats_result = m_daemon->GetDaemonStats();
  if (stats_result.IsErr()) {
    LOGE("Failed to get daemon stats: {}", stats_result.UnwrapErr().Message());
    SendError(res, stats_result.UnwrapErr());
    return;
  }

  json stats_data = stats_result.Unwrap();
  SendSuccess(res, stats_data, "Daemon statistics retrieved successfully");
}

} // namespace http