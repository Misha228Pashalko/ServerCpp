#pragma once
#include <string>
#include <map>
#include <vector>
#include <boost/beast/http.hpp>

namespace Http {
    namespace beast = boost::beast;
    namespace http = beast::http;

    // Клас для обробки HTTP-запитів
    class Request {
    public:
        explicit Request(const http::request<http::string_body>& req);

        // Отримати метод запиту (GET, POST, тощо)
        std::string getMethod() const;

        // Отримати URI запиту
        std::string getUri() const;

        // Отримати версію HTTP
        std::string getHttpVersion() const;

        // Отримати заголовки
        std::map<std::string, std::string> getHeaders() const;

        // Отримати тіло запиту
        std::string getBody() const;

        // Отримати параметри запиту (з query string)
        std::map<std::string, std::string> getQueryParams() const;

        // Отримати значення заголовка
        std::string getHeader(const std::string& name) const;

        // Перевірити наявність заголовка
        bool hasHeader(const std::string& name) const;

        // Отримати IP-адресу клієнта
        std::string getClientIp() const;

    private:
        http::request<http::string_body> request_;
        std::map<std::string, std::string> queryParams_;

        // Розбір query string
        void parseQueryParams();
    };

    // Реалізація методів Request
    Request::Request(const http::request<http::string_body>& req) : request_(req) {
        parseQueryParams();
    }

    std::string Request::getMethod() const {
        return request_.method_string().to_string();
    }

    std::string Request::getUri() const {
        return request_.target().to_string();
    }

    std::string Request::getHttpVersion() const {
        return std::to_string(request_.version());
    }

    std::map<std::string, std::string> Request::getHeaders() const {
        std::map<std::string, std::string> headers;
        for (const auto& header : request_) {
            headers[header.name_string().to_string()] = header.value().to_string();
        }
        return headers;
    }

    std::string Request::getBody() const {
        return request_.body();
    }

    std::map<std::string, std::string> Request::getQueryParams() const {
        return queryParams_;
    }

    std::string Request::getHeader(const std::string& name) const {
        auto it = request_.find(name);
        if (it != request_.end()) {
            return it->value().to_string();
        }
        return "";
    }

    bool Request::hasHeader(const std::string& name) const {
        return request_.find(name) != request_.end();
    }

    std::string Request::getClientIp() const {
        return request_.find("X-Forwarded-For") != request_.end() ? request_["X-Forwarded-For"].to_string() : "";
    }

    void Request::parseQueryParams() {
        std::string target = request_.target().to_string();
        size_t queryStart = target.find('?');
        if (queryStart != std::string::npos) {
            std::string query = target.substr(queryStart + 1);
            std::istringstream iss(query);
            std::string pair;
            while (std::getline(iss, pair, '&')) {
                size_t eq = pair.find('=');
                if (eq != std::string::npos) {
                    std::string key = pair.substr(0, eq);
                    std::string value = pair.substr(eq + 1);
                    queryParams_[key] = value;
                }
            }
        }
    }
}