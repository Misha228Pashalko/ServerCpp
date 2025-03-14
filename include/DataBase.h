#pragma once

#include <sqlite3.h>
#include <memory>
#include <string>
#include <stdexcept>
#include <vector>
#include <iostream>

namespace Database {

    // Клас для обробки винятків, пов'язаних з роботою з базою даних
    class DatabaseException : public std::runtime_error {
    public:
        explicit DatabaseException(const std::string& message)
            : std::runtime_error(message) {}
    };

    class Connection {
    public:
        // Конструктор, який відкриває з'єднання з базою даних
        explicit Connection(const std::string& path) {
            if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
                throw DatabaseException("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
            }
        }

        // Деструктор, який закриває з'єднання з базою даних
        ~Connection() {
            if (db_) {
                sqlite3_close(db_);
            }
        }

        // Виконання SQL-запиту без повернення результату
        void execute(const std::string& query) {
            char* errMsg = nullptr;
            if (sqlite3_exec(db_, query.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
                std::string error = "SQL error: " + std::string(errMsg);
                sqlite3_free(errMsg);
                throw DatabaseException(error);
            }
        }

        // Підготовка SQL-запиту до виконання
        sqlite3_stmt* prepare(const std::string& query) {
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
                throw DatabaseException("Failed to prepare statement: " + std::string(sqlite3_errmsg(db_)));
            }
            return stmt;
        }

        // Виконання підготовленого запиту з параметрами
        void executeStatement(sqlite3_stmt* stmt, const std::vector<std::string>& params) {
            for (size_t i = 0; i < params.size(); ++i) {
                sqlite3_bind_text(stmt, i + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
            }

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                throw DatabaseException("Failed to execute statement: " + std::string(sqlite3_errmsg(db_)));
            }

            sqlite3_reset(stmt);
        }

        // Початок транзакції
        void beginTransaction() {
            execute("BEGIN TRANSACTION;");
        }

        // Підтвердження транзакції
        void commitTransaction() {
            execute("COMMIT;");
        }

        // Відкат транзакції
        void rollbackTransaction() {
            execute("ROLLBACK;");
        }

        // Отримання останнього ID, вставленого в таблицю
        int64_t getLastInsertRowId() const {
            return sqlite3_last_insert_rowid(db_);
        }

    private:
        sqlite3* db_;
    };

} // namespace Database