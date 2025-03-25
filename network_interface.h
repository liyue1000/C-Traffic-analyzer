#pragma once
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <functional>
#include <memory>

// 网卡状态枚举
enum class NetworkStatus {
    INITIAL,        // 初始状态
    READY,          // 就绪状态
    RUNNING,        // 运行中
    ERROR_STATE,    // 错误状态
    STOPPED         // 已停止
};

// 错误类型枚举
enum class ErrorType {
    NONE,                   // 无错误
    INIT_FAILED,            // 初始化失败
    FILTER_ERROR,           // 过滤规则错误
    CAPTURE_ERROR,          // 捕获错误
    THREAD_ERROR,           // 线程错误
    MEMORY_ERROR           // 内存错误
};

// 网卡信息结构体
struct NetworkInterface {
    std::string name;        // 网卡名称
    std::string description; // 网卡描述
    std::string ip_addr;     // IP地址
    std::string subnet_mask; // 子网掩码
    std::string mac_addr;    // MAC地址
};

// 错误信息结构体
struct ErrorInfo {
    ErrorType type;
    std::string message;
    int code;
};

// 网络接口管理类
class NetworkInterfaceManager {
public:
    using ErrorCallback = std::function<void(const ErrorInfo&)>;
    using StatusCallback = std::function<void(NetworkStatus)>;

    NetworkInterfaceManager();
    ~NetworkInterfaceManager();

    // 获取所有网卡信息
    static std::vector<NetworkInterface> GetAllInterfaces();
    
    // 获取指定网卡的MAC地址
    static std::string GetMacAddress(const std::string& adapter_name);
    
    // 将IP地址转换为字符串
    static std::string IpToString(const sockaddr* addr);
    
    // 将MAC地址转换为字符串
    static std::string MacToString(const unsigned char* mac);

    // 开始抓包
    bool StartCapture(const std::string& interface_name);
    
    // 停止抓包
    void StopCapture();

    // 检查是否正在抓包
    bool IsCapturing() const { return is_capturing; }

    // 获取当前状态
    NetworkStatus GetStatus() const { return current_status; }

    // 设置错误回调
    void SetErrorCallback(ErrorCallback callback) { error_callback = callback; }

    // 设置状态回调
    void SetStatusCallback(StatusCallback callback) { status_callback = callback; }

    // 获取最后一次错误
    ErrorInfo GetLastError() const { return last_error; }

    // 重置错误状态
    void ResetError();

    // 设置过滤规则
    bool SetFilter(const std::string& filter);

private:
    pcap_t* capture_handle;
    std::atomic<bool> is_capturing;
    std::thread capture_thread;
    NetworkStatus current_status;
    ErrorInfo last_error;
    ErrorCallback error_callback;
    StatusCallback status_callback;
    std::string current_filter;

    void CaptureThread();
    void UpdateStatus(NetworkStatus new_status);
    void HandleError(ErrorType type, const std::string& message, int code = 0);
    bool TryRecoverFromError();
};