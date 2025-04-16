# 设置 CMake 的最低版本要求
cmake_minimum_required(VERSION 3.16)

# 定义项目名称和语言
project(MyProject LANGUAGES CXX)
# 启用覆盖率选项
option(ENABLE_COVERAGE "Enable coverage reporting" OFF)

if(ENABLE_COVERAGE)
    message("Coverage enabled")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O0 -g --coverage)
        add_link_options(--coverage)
    else()
        message(FATAL_ERROR "Coverage is only supported with GCC or Clang")
    endif()
endif()
# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加子目录
add_subdirectory(src)
add_subdirectory(test)

# 包含头文件目录 (如果有全局的头文件路径)
include_directories(${CMAKE_SOURCE_DIR}/include)
