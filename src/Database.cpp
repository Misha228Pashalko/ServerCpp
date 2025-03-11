#include "Database.h"
#include <stdexcept>

namespace Database {
    Connection::Connection(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Database connection failed");
        }
    }
    
    void Connection::execute(const std::string& query) {
        char* errMsg = nullptr;
        if (sqlite3_exec(db_, query.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
            std::string error(errMsg);
            sqlite3_free(errMsg);
            throw std::runtime_error("SQL error: " + error);
        }
    }
}