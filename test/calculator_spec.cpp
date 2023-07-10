#include <catch2/catch_test_macros.hpp>
#include "calculator.h"

TEST_CASE("Calculator", "[add]") {
    SECTION(".add") {
        SECTION("Should add positive numbers") {
            REQUIRE(add(1, 2) == 3);
        }

        SECTION("Should add negative numbers") {
            REQUIRE(add(1, -2) == -1);
        }
    }
}
