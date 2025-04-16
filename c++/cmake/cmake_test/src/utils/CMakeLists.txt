# 创建一个库
add_library(UtilsLib utils.cc)

# 指定库的头文件路径
target_include_directories(UtilsLib PUBLIC ${CMAKE_SOURCE_DIR}/include)
# 确保没有禁用覆盖率的选项
# target_compile_options(UtilsLib PRIVATE -O0)  # 移除或改为 -O0
