#pragma once

#include "ApiRouter.h"
#include "utils/Macros.h"
#include "utils/Status.h"

#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/Runnable.h"
#include "Poco/ThreadPool.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace http {

/**
 * Helper class to run lambdas in Poco::ThreadPool
 */
class LambdaRunnable : public Poco::Runnable {
public:
  explicit LambdaRunnable(std::function<void()> func)
      : func_(std::move(func)) {}

  void run() override { func_(); }

private:
  std::function<void()> func_;
};

/**
 * HTTP server wrapper that manages the server lifecycle and routing.
 * Provides a high-level interface for starting/stopping the daemon HTTP API.
 */
class HttpServer {
public:
  HttpServer();
  ~HttpServer();

  DISABLE_COPY_AND_MOVE(HttpServer);

  /**
   * Configure server settings.
   * @param host The host address to bind to (default: "0.0.0.0")
   * @param port The port to listen on (default: 34512)
   */
  void Configure(const std::string &host = "0.0.0.0", int port = 34512);

  /**
   * Configure threading and concurrency settings.
   * @param thread_pool_size Number of worker threads for request processing
   * @param request_timeout_sec Request timeout in seconds (0 = no timeout)
   * @param keep_alive_timeout_sec Keep-alive connection timeout in seconds
   */
  void ConfigureThreading(size_t thread_pool_size = 0,
                          int request_timeout_sec = 30,
                          int keep_alive_timeout_sec = 5);

  /**
   * Get the API router for registering routes.
   * @return Reference to the router instance
   */
  ApiRouter &GetRouter();

  /**
   * Start the HTTP server in a background thread.
   * @return Status indicating success or failure
   */
  Status Start();

  /**
   * Stop the HTTP server gracefully.
   * @return Status indicating success or failure
   */
  Status Stop();

  /**
   * Check if the server is currently running.
   * @return True if server is running, false otherwise
   */
  bool IsRunning() const;

  /**
   * Get the server URL.
   * @return Server URL (e.g., "http://0.0.0.0:34512")
   */
  std::string GetServerUrl() const;

  /**
   * Execute an async operation with timeout.
   * @param operation The operation to execute
   * @param timeout_sec Timeout in seconds (0 = no timeout)
   * @return Future containing the result
   */
  template <typename T>
  std::future<T> ExecuteAsync(std::function<T()> operation,
                              int timeout_sec = 30);

  /**
   * Cancel all pending async operations.
   */
  void CancelAsyncOperations();

private:
  /**
   * Thread function for running the HTTP server.
   */
  void ServerThreadFunction();

  /**
   * Setup default routes (health check, etc.).
   */
  void SetupDefaultRoutes();

  std::unique_ptr<Poco::Net::HTTPServer> server_;
  std::unique_ptr<Poco::Net::ServerSocket> server_socket_;
  std::unique_ptr<ApiRouter> router_;

  std::string host_;
  int port_;

  std::atomic<bool> running_;
  std::atomic<bool> should_stop_;

  // Threading and async operation support
  size_t thread_pool_size_;
  int request_timeout_sec_;
  int keep_alive_timeout_sec_;

  // Async operation management
  mutable std::mutex async_operations_mutex_;
  std::vector<std::shared_future<void>> async_operations_;
  std::atomic<bool> cancel_async_operations_;

  // Thread pool for async operations
  std::unique_ptr<Poco::ThreadPool> async_thread_pool_;
};

// Template implementation
template <typename T>
std::future<T> HttpServer::ExecuteAsync(std::function<T()> operation,
                                        int timeout_sec) {
  // Create a promise-future pair
  auto promise = std::make_shared<std::promise<T>>();
  auto future = promise->get_future();

  // Create a task that executes the operation
  auto task = [operation, promise, timeout_sec]() {
    try {
      if constexpr (std::is_same_v<T, void>) {
        operation();
        promise->set_value();
      } else {
        T result = operation();
        promise->set_value(result);
      }
    } catch (...) {
      promise->set_exception(std::current_exception());
    }
  };

  // Submit to async thread pool if available
  if (async_thread_pool_) {
    auto runnable = new LambdaRunnable(task);
    async_thread_pool_->start(*runnable);
  } else {
    // Fallback: execute in a separate thread
    std::thread(task).detach();
  }

  return future;
}

} // namespace http