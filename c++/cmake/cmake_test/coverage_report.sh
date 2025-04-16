#!/bin/bash

rm -r build
mkdir build && cd build

# 启用覆盖率编译
cmake -DENABLE_COVERAGE=ON ..
make

# 运行测试
cd test
ctest

# 捕获覆盖率信息
lcov --capture --directory ../.. --output-file coverage.info

# 确保移除所有无关路径
lcov --remove coverage.info \
    '/usr/include/*' \
    '/usr/include/gtest/*' \
    '/usr/include/gtest/internal/*' \
    '*/bits/*' \
    '*/ext/*' \
    --output-file coverage_filtered.info

# 生成 HTML 覆盖率报告
genhtml coverage_filtered.info --output-directory coverage_report
