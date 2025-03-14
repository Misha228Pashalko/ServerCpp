#pragma once

#include <unordered_map>
#include <regex>
#include <functional>
#include <optional>
#include <string_view>
#include "Request.h"
#include "Response.h"

using namespace std;

namespace Router {
    using Handler = function<void(const Request&, Response&)>;
    class RouteManager{
        public:
        void addRoute(string_view method, string_view pattern, Handler handler);

        optional<Handler> deispatch(const Request& req, Response& res) const;
        private:
        struct Route
        {
            regex pattern;
            Handler handler;
        };
        unordered_multimap<string, Route> routes_;
        
    }
    void RouteManager::addRoute(string_view method, string_view pattern, Handler handler){
        auto range= route_.equal_range(string(method));
        for(auto it= range.first; it != range_second; it++){
            throw runtime_error("Dublicate route detected");
        }
        routes_.emplace(std::string(method), Route{std::regex(pattern.begin(), pattern.end()), handler});

    }
    optional<Handler> RouteManager::deispatch(const Request& req, Response &res) const;{
        auto range = routes_.equal_range(req.method());
        for (auto it = range.first ; it !=range.second; it++){
            if (regex_match(req.path(), it->second.pattern)){
                it->second.handler(req, res);
                return it->second.handler;
            }
        }
    }
}