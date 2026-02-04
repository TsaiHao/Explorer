#include "ApiRouter.h"
#include "utils/Log.h"

#include "Poco/Net/HTTPResponse.h"
#include "Poco/URI.h"

namespace http {

ApiRouter::ApiRouter() = default;

void ApiRouter::RegisterPost(const std::string &path,
                             std::shared_ptr<RequestHandler> handler) {
  LOGI("Registering POST route: {}", path);
  post_routes_[path] = handler;
}

void ApiRouter::RegisterGet(const std::string &path,
                            std::shared_ptr<RequestHandler> handler) {
  LOGI("Registering GET route: {}", path);
  get_routes_[path] = handler;
}

Poco::Net::HTTPRequestHandler *
ApiRouter::createRequestHandler(const Poco::Net::HTTPServerRequest &request) {
  const std::string &method = request.getMethod();
  const std::string &path = request.getURI();

  LOGD("Routing request: {} {}", method, path);

  // Find matching handler based on method and path
  std::shared_ptr<RequestHandler> handler = nullptr;

  if (method == "POST") {
    auto it = post_routes_.find(path);
    if (it != post_routes_.end()) {
      handler = it->second;
    }
  } else if (method == "GET") {
    auto it = get_routes_.find(path);
    if (it != get_routes_.end()) {
      handler = it->second;
    }
  }

  if (handler) {
    return new RoutedRequestHandler(handler, middleware_);
  }

  // No handler found
  LOGW("No handler found for {} {}", method, path);
  return nullptr;
}

void ApiRouter::AddMiddleware(
    std::function<bool(const Poco::Net::HTTPServerRequest &,
                       Poco::Net::HTTPServerResponse &)>
        middleware) {
  middleware_.push_back(std::move(middleware));
  LOGI("Added middleware function (total: {})", middleware_.size());
}

// RoutedRequestHandler implementation
ApiRouter::RoutedRequestHandler::RoutedRequestHandler(
    std::shared_ptr<RequestHandler> handler,
    const std::vector<std::function<bool(const Poco::Net::HTTPServerRequest &,
                                         Poco::Net::HTTPServerResponse &)>>
        &middleware)
    : handler_(handler), middleware_(middleware) {}

void ApiRouter::RoutedRequestHandler::handleRequest(
    Poco::Net::HTTPServerRequest &request,
    Poco::Net::HTTPServerResponse &response) {
  // Apply middleware functions
  for (const auto &middleware : middleware_) {
    if (!middleware(request, response)) {
      // Middleware returned false, stop processing
      LOGW("Request blocked by middleware for path: {}", request.getURI());
      return;
    }
  }

  // Set common headers
  response.setContentType("application/json");
  response.set("Cache-Control", "no-cache, no-store, must-revalidate");

  // Add CORS headers (if needed for web clients)
  response.set("Access-Control-Allow-Origin", "*");
  response.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.set("Access-Control-Allow-Headers", "Content-Type");

  try {
    // Call the actual handler (use the base class handleRequest method)
    handler_->handleRequest(request, response);
  } catch (const std::exception &e) {
    LOGE("Exception in handler for path {}: {}", request.getURI(), e.what());

    // Send error response
    json error_response = {{"status", "error"},
                           {"message", "Internal server error"},
                           {"details", {{"exception", e.what()}}}};

    std::string response_body = error_response.dump(2);
    response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    response.setContentType("application/json");
    response.setContentLength(response_body.length());

    std::ostream &out = response.send();
    out << response_body;
  }
}

} // namespace http