#include "Server.h"
#include <thread>
#include "Utils.h"
#include "Security.h"

using namespace HttpServer;

Server::Server(unsigned short port, const std::string& dbPath) 
    : port_(port), 
      acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)),
      dbConnection_(dbPath) {
    
    // Додавання стандартних маршрутів
    router_.addRoute("GET", "/api/data", [this](const Request& req, Response& res) {
        // Обробка запиту
    });
}

void Server::start() {
    Security::log("Server started on port " + std::to_string(port_));
    acceptConnection();
    io_context_.run();
}

void Server::acceptConnection() {
    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            std::thread(&Server::handleRequest, this, std::move(socket)).detach();
        }
        acceptConnection();
    });
}