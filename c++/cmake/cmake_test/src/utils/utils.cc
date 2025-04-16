#include "utils.h"
#include <limits>
#include <stdexcept>

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    // 检查是否存在溢出的可能性
    if (a > 0 && b > 0 && a > std::numeric_limits<int>::max() / b) {
        throw std::overflow_error("Overflow occurred while multiplying");
    }
    if (a < 0 && b < 0 && a < std::numeric_limits<int>::max() / b) {
        throw std::overflow_error("Overflow occurred while multiplying");
    }
    if (a > 0 && b < 0 && b < std::numeric_limits<int>::min() / a) {
        throw std::overflow_error("Overflow occurred while multiplying");
    }
    if (a < 0 && b > 0 && a < std::numeric_limits<int>::min() / b) {
        throw std::overflow_error("Overflow occurred while multiplying");
    }
    return a * b;
}