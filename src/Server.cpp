#include "Server.h"
#include <thread>
#include <vector>
#include <memory>
#include <boost/asio/ssl.hpp>
#include "Utils.h"
#include "Security.h"

using namespace HttpServer;

Server::Server(unsigned short port, const std::string& dbPath, const std::string& certPath, const std::string& keyPath)
    : port_(port),
      acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)),
      dbConnection_(dbPath),
      sslContext_(boost::asio::ssl::context::sslv23) {
    
    // Налаштування SSL контексту
    sslContext_.set_options(boost::asio::ssl::context::default_workarounds |
                            boost::asio::ssl::context::no_sslv2 |
                            boost::asio::ssl::context::single_dh_use);
    sslContext_.use_certificate_chain_file(certPath);
    sslContext_.use_private_key_file(keyPath, boost::asio::ssl::context::pem);

    // Додавання стандартних маршрутів
    router_.addRoute("GET", "/api/data", [this](const Request& req, Response& res) {
        // Обробка запиту
    });

    // Ініціалізація пулу потоків
    unsigned int threadPoolSize = std::thread::hardware_concurrency();
    for (unsigned int i = 0; i < threadPoolSize; ++i) {
        threadPool_.emplace_back([this]() {
            io_context_.run();
        });
    }
}

void Server::start() {
    Security::log("Server started on port " + std::to_string(port_));
    acceptConnection();
}

void Server::acceptConnection() {
    auto socket = std::make_shared<boost::asio::ssl::stream<tcp::socket>>(io_context_, sslContext_);
    acceptor_.async_accept((*socket).lowest_layer(), [this, socket](boost::system::error_code ec) {
        if (!ec) {
            // Виконання SSL handshake
            (*socket).async_handshake(boost::asio::ssl::stream_base::server,
                [this, socket](const boost::system::error_code& handshakeEc) {
                    if (!handshakeEc) {
                        // Додавання завдання до пулу потоків
                        io_context_.post([this, socket]() {
                            handleRequest(std::move(*socket));
                        });
                    }
                });
        }
        acceptConnection();
    });
}

void Server::handleRequest(boost::asio::ssl::stream<tcp::socket> socket) {
    try {
        // Читання запиту
        boost::asio::streambuf buffer;
        boost::asio::read_until(socket, buffer, "\r\n\r\n");

        // Парсинг запиту
        std::istream requestStream(&buffer);
        std::string requestLine;
        std::getline(requestStream, requestLine);

        // Обробка запиту
        Request req;
        Response res;
        router_.handleRequest(req, res);

        // Відправлення відповіді
        boost::asio::write(socket, boost::asio::buffer(res.toString()));
    } catch (std::exception& e) {
        Security::log("Error handling request: " + std::string(e.what()));
    }
}

Server::~Server() {
    // Зупинка всіх потоків
    io_context_.stop();
    for (auto& thread : threadPool_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}