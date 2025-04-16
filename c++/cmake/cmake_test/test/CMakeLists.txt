# 添加测试可执行文件
add_executable(Tests main.cc)

# 链接需要测试的库
target_link_libraries(Tests PRIVATE UtilsLib)

# 指定 include 路径 (可选，测试代码需要的头文件)
target_include_directories(Tests PRIVATE ${CMAKE_SOURCE_DIR}/include)
# 链接系统安装的 gtest 库
find_package(GTest REQUIRED)
target_link_libraries(Tests PRIVATE GTest::GTest GTest::Main)
# if(ENABLE_COVERAGE)
#     # 包含目标代码的路径以生成完整覆盖率报告
#     target_link_options(Tests PRIVATE --coverage)
# endif()

# 注册测试
enable_testing()
add_test(NAME Tests COMMAND Tests)