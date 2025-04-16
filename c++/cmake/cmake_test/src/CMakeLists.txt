# src 目录下的 CMake 文件

# 包含子目录
add_subdirectory(utils)

# 添加可执行文件
add_executable(MyApp main.cc)

# 链接 utils 库到主程序
target_link_libraries(MyApp PRIVATE UtilsLib)

# 设置 include 路径 (可以对 MyApp 单独设置)
target_include_directories(MyApp PRIVATE ${CMAKE_SOURCE_DIR}/include)
