#pragma once
#include <unordered_map>
#include <regex>
#include "Request.h"
#include "Response.h"

namespace Router {
    using Handler = std::function<void(const Request&, Response&)>;
    
    class RouteManager {
    public:
        void addRoute(const std::string& method, const std::string& pattern, Handler handler);
        bool dispatch(const Request& req, Response& res) const;
        
    private:
        struct Route {
            std::regex pattern;
            Handler handler;
        };
        
        std::unordered_multimap<std::string, Route> routes_;
    };
}