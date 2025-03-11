#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <thread>
#include "Database.h"
#include "Security.h"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

// Обробник HTTP запитів
void handle_request(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    res.version(req.version());
    res.keep_alive(false);

    if (req.method() == http::verb::get && req.target() == "/api/calculate") {
        // Приклад обчислення
        double result = performCalculation(5, 10); // Виклик функції обчислення
        res.result(http::status::ok);
        res.set(http::field::content_type, "application/json");
        res.body() = "{\"result\": " + std::to_string(result) + "}";
    } else {
        res.result(http::status::not_found);
        res.set(http::field::content_type, "text/plain");
        res.body() = "404 Not Found";
    }

    res.prepare_payload();
}

// Запуск сервера
void run_server() {
    try {
        net::io_context ioc{1};
        tcp::acceptor acceptor{ioc, {tcp::v4(), 8080}};

        std::cout << "Сервер запущено на http://localhost:8080\n";

        while (true) {
            tcp::socket socket{ioc};
            acceptor.accept(socket);

            beast::flat_buffer buffer;
            http::request<http::string_body> req;
            http::read(socket, buffer, req);

            http::response<http::string_body> res;
            handle_request(req, res);

            http::write(socket, res);
            socket.shutdown(tcp::socket::shutdown_send);
        }
    } catch (const std::exception& e) {
        std::cerr << "Помилка: " << e.what() << std::endl;
    }
}

int main() {
    // Ініціалізація бази даних
    Database::initialize();

    // Запуск сервера
    run_server();

    return 0;
}