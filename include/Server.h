#pragma once
#include <boost/asio.hpp>
#include <functional>
#include "Router.h"
#include "Database.h"
#include "Security.h"

namespace HttpServer {
    using namespace boost::asio;
    using namespace boost::beast;
    
    class Server {
    public:
        Server(unsigned short port, const std::string& dbPath);
        void start();
        void addRoute(const std::string& method, const std::string& path, Router::Handler handler);
        
    private:
        void acceptConnection();
        void handleRequest(tcp::socket socket);
        
        ip::tcp::acceptor acceptor_;
        Database::Connection dbConnection_;
        Router router_;
        const unsigned short port_;
    };
}