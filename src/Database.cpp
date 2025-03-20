#include "Database.h"
#include <stdexcept>
#include <memory>
#include <sqlite3.h>
#include <iostream>

using namespace std;

namespace Database {

    // Конструктор для підключення до бази даних
    Connection::Connection(const string& path) {
        sqlite3* db = nullptr;
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            throw runtime_error("Помилка при підключенні до бази даних: " + string(sqlite3_errmsg(db)));
        }
        db_ = unique_ptr<sqlite3, decltype(&sqlite3_close)>(db, sqlite3_close);
    }

    // Виконання SQL-запиту без повернення результату (наприклад, INSERT, UPDATE, DELETE)
    void Connection::execute(const string& query) {
        char* errMsg = nullptr;
        if (sqlite3_exec(db_.get(), query.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
            string error(errMsg);
            sqlite3_free(errMsg);
            throw runtime_error("Помилка SQL: " + error);
        }
    }

    // Виконання SQL-запиту з поверненням результатів (наприклад, SELECT)
    vector<vector<string>> Connection::query(const string& query) {
        vector<vector<string>> result;
        char* errMsg = nullptr;

        // Callback-функція, яка викликається для кожного рядка результату
        auto callback = [](void* data, int argc, char** argv, char** colNames) -> int {
            auto* result = static_cast<vector<vector<string>>*>(data);
            vector<string> row;
            for (int i = 0; i < argc; i++) {
                row.push_back(argv[i] ? argv[i] : "NULL");
            }
            result->push_back(row);
            return 0;
        };

        if (sqlite3_exec(db_.get(), query.c_str(), callback, &result, &errMsg) != SQLITE_OK) {
            string error(errMsg);
            sqlite3_free(errMsg);
            throw runtime_error("Помилка SQL: " + error);
        }

        return result;
    }

    // Отримання останнього вставленого ID (після INSERT)
    int Connection::getLastInsertId() const {
        return sqlite3_last_insert_rowid(db_.get());
    }

    // Початок транзакції
    void Connection::beginTransaction() {
        execute("BEGIN TRANSACTION;");
    }

    // Підтвердження транзакції
    void Connection::commitTransaction() {
        execute("COMMIT;");
    }

    // Відкат транзакції
    void Connection::rollbackTransaction() {
        execute("ROLLBACK;");
    }
}