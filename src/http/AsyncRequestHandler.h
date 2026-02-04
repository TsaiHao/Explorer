#pragma once

#include "RequestHandler.h"
#include "nlohmann/json.hpp"
#include "utils/Status.h"

#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"

#include <chrono>
#include <functional>
#include <future>

namespace http {

/**
 * Base class for request handlers that support async operations.
 * Provides utilities for handling long-running operations with timeouts.
 */
class AsyncRequestHandler : public RequestHandler {
public:
  explicit AsyncRequestHandler(int default_timeout_sec = 30);
  virtual ~AsyncRequestHandler() = default;

protected:
  /**
   * Execute an async operation with timeout and proper response handling.
   * @param operation The operation to execute asynchronously
   * @param res The HTTP response object to send results to
   * @param timeout_sec Timeout in seconds (0 = use default)
   */
  template <typename T>
  void ExecuteAsync(std::function<Result<T, Status>()> operation,
                    Poco::Net::HTTPServerResponse &res, int timeout_sec = 0);

  /**
   * Check if the async operation should be cancelled.
   * Long-running operations should periodically check this.
   * @return True if the operation should be cancelled
   */
  bool ShouldCancel() const;

  /**
   * Mark the handler as being cancelled (called automatically on timeout).
   */
  void Cancel();

private:
  int default_timeout_sec_;
  std::atomic<bool> cancelled_;
};

// Template implementation
template <typename T>
void AsyncRequestHandler::ExecuteAsync(
    std::function<Result<T, Status>()> operation,
    Poco::Net::HTTPServerResponse &res, int timeout_sec) {
  if (timeout_sec <= 0) {
    timeout_sec = default_timeout_sec_;
  }

  // Launch the operation asynchronously
  auto future =
      std::async(std::launch::async, [operation]() -> Result<T, Status> {
        try {
          return operation();
        } catch (const std::exception &e) {
          return Err<Status>(SdkFailure(
              std::string("Async operation exception: ") + e.what()));
        } catch (...) {
          return Err<Status>(SdkFailure("Unknown async operation exception"));
        }
      });

  // Wait for completion with timeout
  auto status = future.wait_for(std::chrono::seconds(timeout_sec));

  if (status == std::future_status::timeout) {
    // Operation timed out
    Cancel();
    SendError(res, 408, "Request timeout: operation took too long");
    return;
  }

  if (status == std::future_status::deferred) {
    // This shouldn't happen with std::launch::async
    Cancel();
    SendError(res, 500, "Internal error: async operation was deferred");
    return;
  }

  // Get the result
  auto result = future.get();

  if (result.IsErr()) {
    SendError(res, result.UnwrapErr());
    return;
  }

  if constexpr (std::is_same_v<T, nlohmann::json>) {
    SendSuccess(res, result.Unwrap());
  } else {
    // For other types, convert to JSON or handle appropriately
    nlohmann::json response_data = {{"result", result.Unwrap()}};
    SendSuccess(res, response_data);
  }
}

} // namespace http