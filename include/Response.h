#pragma once
#include <string>
#include <map>
#include <boost/beast/http.hpp>

namespace Http {
    namespace beast = boost::beast;
    namespace http = beast::http;

    // Клас для формування HTTP-відповідей
    class Response {
    public:
        Response();

        // Встановити статус відповіді
        void setStatus(http::status status);

        // Встановити тіло відповіді
        void setBody(const std::string& body);

        // Встановити заголовок
        void setHeader(const std::string& name, const std::string& value);

        // Отримати статус відповіді
        http::status getStatus() const;

        // Отримати тіло відповіді
        std::string getBody() const;

        // Отримати заголовки
        std::map<std::string, std::string> getHeaders() const;

        // Отримати об'єкт відповіді для використання в Boost.Beast
        http::response<http::string_body> getBeastResponse() const;

    private:
        http::response<http::string_body> response_;
    };

    // Реалізація методів Response
    Response::Response() {
        response_.version(11); // HTTP/1.1
        response_.set(http::field::server, "C++ Server");
    }

    void Response::setStatus(http::status status) {
        response_.result(status);
    }

    void Response::setBody(const std::string& body) {
        response_.body() = body;
        response_.prepare_payload();
    }

    void Response::setHeader(const std::string& name, const std::string& value) {
        response_.set(name, value);
    }

    http::status Response::getStatus() const {
        return response_.result();
    }

    std::string Response::getBody() const {
        return response_.body();
    }

    std::map<std::string, std::string> Response::getHeaders() const {
        std::map<std::string, std::string> headers;
        for (const auto& header : response_) {
            headers[header.name_string().to_string()] = header.value().to_string();
        }
        return headers;
    }

    http::response<http::string_body> Response::getBeastResponse() const {
        return response_;
    }
}