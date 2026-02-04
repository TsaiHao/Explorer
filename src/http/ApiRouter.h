#pragma once

#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "RequestHandler.h"

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace http {

/**
 * HTTP API router for registering and dispatching requests to handlers.
 * Manages route registration and provides middleware support.
 */
class ApiRouter : public Poco::Net::HTTPRequestHandlerFactory {
public:
  ApiRouter();
  ~ApiRouter() = default;

  /**
   * Create a request handler for the given request (Poco::Net interface).
   * @param request The HTTP request
   * @return Pointer to request handler, or nullptr if no handler found
   */
  Poco::Net::HTTPRequestHandler *
  createRequestHandler(const Poco::Net::HTTPServerRequest &request) override;

  /**
   * Register a POST route with a specific handler.
   * @param path The route path (e.g., "/api/v1/session")
   * @param handler The request handler for this route
   */
  void RegisterPost(const std::string &path,
                    std::shared_ptr<RequestHandler> handler);

  /**
   * Register a GET route with a specific handler.
   * @param path The route path (e.g., "/health")
   * @param handler The request handler for this route
   */
  void RegisterGet(const std::string &path,
                   std::shared_ptr<RequestHandler> handler);

  /**
   * Add a middleware function to be called before all requests.
   * @param middleware The middleware function
   */
  void AddMiddleware(std::function<bool(const Poco::Net::HTTPServerRequest &,
                                        Poco::Net::HTTPServerResponse &)>
                         middleware);

private:
  /**
   * Wrapper class that applies middleware and calls the handler.
   */
  class RoutedRequestHandler : public Poco::Net::HTTPRequestHandler {
  public:
    RoutedRequestHandler(
        std::shared_ptr<RequestHandler> handler,
        const std::vector<
            std::function<bool(const Poco::Net::HTTPServerRequest &,
                               Poco::Net::HTTPServerResponse &)>> &middleware);

    void handleRequest(Poco::Net::HTTPServerRequest &request,
                       Poco::Net::HTTPServerResponse &response) override;

  private:
    std::shared_ptr<RequestHandler> handler_;
    const std::vector<std::function<bool(const Poco::Net::HTTPServerRequest &,
                                         Poco::Net::HTTPServerResponse &)>>
        &middleware_;
  };

  // Route storage
  std::unordered_map<std::string, std::shared_ptr<RequestHandler>> post_routes_;
  std::unordered_map<std::string, std::shared_ptr<RequestHandler>> get_routes_;

  // Middleware functions
  std::vector<std::function<bool(const Poco::Net::HTTPServerRequest &,
                                 Poco::Net::HTTPServerResponse &)>>
      middleware_;
};

} // namespace http