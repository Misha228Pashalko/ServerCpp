#pragma once
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <boost/beast/http.hpp>

namespace Http {
    namespace beast = boost::beast;
    namespace http = beast::http;

    // Базовий інтерфейс для обробки запитів
    class IRequestHandler {
    public:
        virtual ~IRequestHandler() = default;
        virtual void handleRequest(const http::request<http::string_body>& req, http::response<http::string_body>& res) = 0;
    };

    // Інтерфейс для маршрутизації
    class IRouter {
    public:
        virtual ~IRouter() = default;
        virtual void addRoute(const std::string& method, const std::string& path, std::function<void(const http::request<http::string_body>&, http::response<http::string_body>&)> handler) = 0;
        virtual bool routeRequest(const http::request<http::string_body>& req, http::response<http::string_body>& res) = 0;
    };

    // Інтерфейс для сесії клієнта
    class IClientSession {
    public:
        virtual ~IClientSession() = default;
        virtual void start() = 0;
        virtual void sendResponse(const http::response<http::string_body>& res) = 0;
    };

    // Інтерфейс для сервера
    class IServer {
    public:
        virtual ~IServer() = default;
        virtual void start() = 0;
        virtual void stop() = 0;
        virtual void addRoute(const std::string& method, const std::string& path, std::function<void(const http::request<http::string_body>&, http::response<http::string_body>&)> handler) = 0;
    };

    // Інтерфейс для middleware
    class IMiddleware {
    public:
        virtual ~IMiddleware() = default;
        virtual void processRequest(http::request<http::string_body>& req, http::response<http::string_body>& res) = 0;
        virtual void processResponse(http::request<http::string_body>& req, http::response<http::string_body>& res) = 0;
    };
}