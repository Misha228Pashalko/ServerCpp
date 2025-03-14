#include <gtest/gtest.h>
#include "main.cpp"  // Include the source file to test

TEST(HandleRequestTest, PositiveIntegers) {
    http::request<http::string_body> req;
    req.method(http::verb::get);
    req.target("/api/calculate");
    req.version(11);  // HTTP/1.1

    http::response<http::string_body> res;

    // Mock the performCalculation function to return a floating-point result
    auto original_performCalculation = performCalculation;
    performCalculation = [](double a, double b) -> double {
        return a + b;
    };

    handle_request(req, res);

    // Restore the original performCalculation function
    performCalculation = original_performCalculation;

    ASSERT_EQ(res.result(), http::status::ok);
    ASSERT_EQ(res.get(http::field::content_type), "application/json");

    // Parse the JSON response
    auto json = nlohmann::json::parse(res.body());
    ASSERT_DOUBLE_EQ(json["result"].get<double>(), 15.0);  // 5 + 10 = 15.0

    ASSERT_EQ(res.version(), 11);
    ASSERT_FALSE(res.keep_alive());
}

TEST_CASE("handle_request returns correct result for negative integer inputs", "[handle_request]") {
    http::request<http::string_body> req;
    http::response<http::string_body> res;

    req.method(http::verb::get);
    req.target("/api/calculate");
    req.version(11);  // HTTP/1.1

    // Mock the performCalculation function to return a result for negative inputs
    auto mock_performCalculation = [](int a, int b) -> double {
        return static_cast<double>(a + b);
    };

    // Replace the original performCalculation with the mock
    auto original_performCalculation = performCalculation;
    performCalculation = mock_performCalculation;

    handle_request(req, res);

    // Restore the original performCalculation function
    performCalculation = original_performCalculation;

    REQUIRE(res.result() == http::status::ok);
    REQUIRE(res.at(http::field::content_type) == "application/json");

    // Parse the JSON response
    auto json = nlohmann::json::parse(res.body());
    REQUIRE(json["result"] == 15.0);  // 5 + 10 = 15

    // Check other response properties
    REQUIRE(res.version() == 11);
    REQUIRE(!res.keep_alive());
}
