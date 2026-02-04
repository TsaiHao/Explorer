#include "HttpServer.h"
#include "utils/Log.h"

#include "Poco/Exception.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/SocketAddress.h"

#include <chrono>

namespace http {

namespace {

/**
 * Simple health check handler.
 */
class HealthHandler : public RequestHandler {
public:
  void Handle(Poco::Net::HTTPServerRequest &,
              Poco::Net::HTTPServerResponse &res) override {
    json health_data = {
        {"status", "healthy"},
        {"service", "explorer-daemon"},
        {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count()}};

    SendSuccess(res, health_data);
  }
};

} // anonymous namespace

HttpServer::HttpServer()
    : router_(std::make_unique<ApiRouter>()), host_("0.0.0.0"), port_(34512),
      running_(false), should_stop_(false),
      thread_pool_size_(0), // 0 = use default
      request_timeout_sec_(30), keep_alive_timeout_sec_(5),
      cancel_async_operations_(false) {

  SetupDefaultRoutes();
}

HttpServer::~HttpServer() {
  if (IsRunning()) {
    Stop();
  }
}

void HttpServer::Configure(const std::string &host, int port) {
  if (IsRunning()) {
    LOGW("Cannot configure server while it's running");
    return;
  }

  host_ = host;
  port_ = port;
  LOGI("Configured HTTP server: {}:{}", host_, port_);
}

void HttpServer::ConfigureThreading(size_t thread_pool_size,
                                    int request_timeout_sec,
                                    int keep_alive_timeout_sec) {
  if (IsRunning()) {
    LOGW("Cannot configure threading while server is running");
    return;
  }

  thread_pool_size_ = thread_pool_size;
  request_timeout_sec_ = request_timeout_sec;
  keep_alive_timeout_sec_ = keep_alive_timeout_sec;

  // Create async thread pool for long-running operations
  size_t async_pool_size = std::max(2u, thread_pool_size_ / 2);
  async_thread_pool_ = std::make_unique<Poco::ThreadPool>(1, async_pool_size);

  LOGI("Configured HTTP server threading: pool_size={}, request_timeout={}s, "
       "keep_alive={}s",
       thread_pool_size_, request_timeout_sec_, keep_alive_timeout_sec_);
}

ApiRouter &HttpServer::GetRouter() { return *router_; }

Status HttpServer::Start() {
  if (running_) {
    return Status(StatusCode::kInvalidState, "Server is already running");
  }

  LOGI("Starting HTTP server on {}:{}", host_, port_);

  try {
    // Create server socket
    Poco::Net::SocketAddress address(host_, port_);
    server_socket_ = std::make_unique<Poco::Net::ServerSocket>(address);

    // Create server parameters
    auto params = new Poco::Net::HTTPServerParams();
    if (thread_pool_size_ > 0) {
      params->setMaxThreads(thread_pool_size_);
    }
    params->setMaxQueued(100);
    params->setKeepAlive(keep_alive_timeout_sec_ > 0);
    if (keep_alive_timeout_sec_ > 0) {
      params->setKeepAliveTimeout(Poco::Timespan(keep_alive_timeout_sec_, 0));
    }
    if (request_timeout_sec_ > 0) {
      params->setTimeout(Poco::Timespan(request_timeout_sec_, 0));
    }

    // Create HTTP server with router as request handler factory
    server_ = std::make_unique<Poco::Net::HTTPServer>(router_.get(),
                                                      *server_socket_, params);

    // Start the server
    server_->start();
    running_ = true;

    LOGI("HTTP server started successfully on {}", GetServerUrl());
    return Status();

  } catch (const Poco::Exception &e) {
    LOGE("Failed to start HTTP server: {}", e.displayText());
    return Status(StatusCode::kSdkFailure,
                  "Failed to start HTTP server: " + e.displayText());
  } catch (const std::exception &e) {
    LOGE("Failed to start HTTP server: {}", e.what());
    return Status(StatusCode::kSdkFailure,
                  "Failed to start HTTP server: " + std::string(e.what()));
  }
}

Status HttpServer::Stop() {
  if (!running_) {
    return Status(StatusCode::kInvalidState, "Server is not running");
  }

  LOGI("Stopping HTTP server...");

  // Cancel all async operations first
  CancelAsyncOperations();

  try {
    should_stop_ = true;
    if (server_) {
      server_->stop();
    }
    running_ = false;

    LOGI("HTTP server stopped successfully");
    return Status();

  } catch (const Poco::Exception &e) {
    LOGE("Error stopping HTTP server: {}", e.displayText());
    return Status(StatusCode::kSdkFailure, "Error stopping server");
  }
}

bool HttpServer::IsRunning() const { return running_; }

std::string HttpServer::GetServerUrl() const {
  std::string protocol = "http";
  return protocol + "://" + host_ + ":" + std::to_string(port_);
}

void HttpServer::CancelAsyncOperations() {
  std::lock_guard<std::mutex> lock(async_operations_mutex_);
  cancel_async_operations_ = true;

  // Clear all pending operations
  async_operations_.clear();

  LOGI("Cancelled all pending async operations");
}

void HttpServer::SetupDefaultRoutes() {
  // Register basic health check route
  router_->RegisterGet("/health", std::make_shared<HealthHandler>());
  LOGI("Registered default routes");
}

} // namespace http