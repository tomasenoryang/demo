#include <gtest/gtest.h>
#include "utils.h"

int a(){
    std::cout << "hahahah!" << std::endl;
    return 0;
}
// 测试 add 函数
TEST(UtilsTest, AddFunction) {
    EXPECT_EQ(add(2, 3), 5);       // 2 + 3 = 5
    EXPECT_EQ(add(-1, 1), 0);      // -1 + 1 = 0
    EXPECT_EQ(add(0, 0), 0);       // 0 + 0 = 0
}

// 测试 multiply 函数
TEST(UtilsTest, MultiplyFunction) {
    EXPECT_EQ(multiply(2, 3), 6);  // 2 * 3 = 6
    EXPECT_EQ(multiply(-1, 3), -3);// -1 * 3 = -3
    EXPECT_EQ(multiply(0, 5), 5);  // 0 * 5 = 0
}

// 测试运行入口
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
