cmake_minimum_required(VERSION 3.10)

# 项目名称和语言
project(NetworkAnalyzer VERSION 1.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Npcap SDK路径
set(NPCAP_SDK_DIR "C:/Users/liyue/Desktop/jisuanji/npcap-sdk-1.15")

# 添加头文件目录
include_directories(${NPCAP_SDK_DIR}/Include)

# 添加库文件目录
link_directories(${NPCAP_SDK_DIR}/Lib/x64)

# 源文件
set(SOURCES
    main.cpp
    network_interface.cpp
    network_interface.h
)

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 链接库文件
target_link_libraries(${PROJECT_NAME}
    wpcap
    Ws2_32
    comctl32
    iphlpapi
)

# 编译选项
if(MSVC)
    # 使用多线程静态运行时库
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    
    # 禁用安全警告
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)