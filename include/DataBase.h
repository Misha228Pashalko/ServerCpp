#pragma once
#include <sqlite3.h>
#include <memory>
#include <string>

namespace Database {
    class Connection {
    public:
        explicit Connection(const std::string& path);
        ~Connection();
        
        void execute(const std::string& query);
        sqlite3_stmt* prepare(const std::string& query);
        
    private:
        sqlite3* db_;
    };
}