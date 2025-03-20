#include <gtest/gtest.h>
#include "Database.h"
#include <memory>
#include <vector>
#include <string>

class DatabaseTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
    }

    std::unique_ptr<Database::Connection> createTestConnection() {
        return std::make_unique<Database::Connection>(":memory:");
    }
};

