#include "network_interface.h"
#include <iphlpapi.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#pragma comment(lib, "iphlpapi.lib")

NetworkInterfaceManager::NetworkInterfaceManager()
    : capture_handle(nullptr)
    , is_capturing(false)
    , current_status(NetworkStatus::INITIAL) {}

NetworkInterfaceManager::~NetworkInterfaceManager() {
    StopCapture();
}

void NetworkInterfaceManager::UpdateStatus(NetworkStatus new_status) {
    current_status = new_status;
    if (status_callback) {
        status_callback(new_status);
    }
}

void NetworkInterfaceManager::HandleError(ErrorType type, const std::string& message, int code) {
    last_error = {type, message, code};
    if (error_callback) {
        error_callback(last_error);
    }
    UpdateStatus(NetworkStatus::ERROR_STATE);
}

void NetworkInterfaceManager::ResetError() {
    last_error = {ErrorType::NONE, "", 0};
    UpdateStatus(NetworkStatus::READY);
}

bool NetworkInterfaceManager::TryRecoverFromError() {
    switch (last_error.type) {
        case ErrorType::INIT_FAILED:
            // 尝试重新初始化
            return false;
        case ErrorType::FILTER_ERROR:
            // 恢复到上一个有效的过滤规则
            return SetFilter(current_filter);
        case ErrorType::CAPTURE_ERROR:
            // 尝试重新启动捕获
            return false;
        default:
            return false;
    }
}

bool NetworkInterfaceManager::SetFilter(const std::string& filter) {
    if (!capture_handle) {
        HandleError(ErrorType::INIT_FAILED, "Capture handle not initialized");
        return false;
    }

    struct bpf_program fp;
    if (pcap_compile(capture_handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        HandleError(ErrorType::FILTER_ERROR, "Failed to compile filter: " + 
                    std::string(pcap_geterr(capture_handle)));
        return false;
    }

    if (pcap_setfilter(capture_handle, &fp) == -1) {
        pcap_freecode(&fp);
        HandleError(ErrorType::FILTER_ERROR, "Failed to set filter: " + 
                    std::string(pcap_geterr(capture_handle)));
        return false;
    }

    pcap_freecode(&fp);
    current_filter = filter;
    return true;
}

bool NetworkInterfaceManager::StartCapture(const std::string& interface_name) {
    if (is_capturing) {
        return false;
    }

    UpdateStatus(NetworkStatus::READY);
    char errbuf[PCAP_ERRBUF_SIZE];
    int retry_count = 0;
    const int MAX_RETRIES = 3;

    while (retry_count < MAX_RETRIES) {
        capture_handle = pcap_open_live(interface_name.c_str(),
                                      65536,  // 抓取数据包的最大字节数
                                      1,      // 混杂模式
                                      1000,   // 读取超时时间
                                      errbuf);

        if (capture_handle != nullptr) {
            break;
        }

        retry_count++;
        Sleep(1000); // 等待1秒后重试
    }

    if (capture_handle == nullptr) {
        HandleError(ErrorType::INIT_FAILED, "Failed to initialize network interface after " + 
                    std::to_string(MAX_RETRIES) + " attempts: " + std::string(errbuf));
        return false;
    }

    is_capturing = true;
    try {
        capture_thread = std::thread(&NetworkInterfaceManager::CaptureThread, this);
        SetThreadPriority(reinterpret_cast<HANDLE>(capture_thread.native_handle()), THREAD_PRIORITY_HIGHEST);
        UpdateStatus(NetworkStatus::RUNNING);
    } catch (const std::exception& e) {
        is_capturing = false;
        pcap_close(capture_handle);
        capture_handle = nullptr;
        HandleError(ErrorType::THREAD_ERROR, "Failed to create capture thread: " + std::string(e.what()));
        return false;
    }

    return true;
}

void NetworkInterfaceManager::StopCapture() {
    if (is_capturing) {
        is_capturing = false;

        if (capture_thread.joinable()) {
            std::thread temp_thread([this]() {
                if (capture_thread.joinable()) {
                    capture_thread.join();
                }
            });

            if (temp_thread.joinable()) {
                temp_thread.join();
            }
        }

        if (capture_handle) {
            pcap_close(capture_handle);
            capture_handle = nullptr;
        }

        UpdateStatus(NetworkStatus::STOPPED);
    }
}

void NetworkInterfaceManager::CaptureThread() {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (is_capturing) {
        try {
            int result = pcap_next_ex(capture_handle, &header, &packet);
            if (result == 0) continue;  // 超时
            if (result < 0) {
                HandleError(ErrorType::CAPTURE_ERROR, "Error capturing packet: " + 
                            std::string(pcap_geterr(capture_handle)));
                break;
            }

            // 这里可以添加数据包处理的代码
        } catch (const std::exception& e) {
            HandleError(ErrorType::CAPTURE_ERROR, e.what());
            Sleep(100); // 避免在错误情况下过度消耗CPU
        }
    }
}

std::vector<NetworkInterface> NetworkInterfaceManager::GetAllInterfaces() {
    std::vector<NetworkInterface> interfaces;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        return interfaces;
    }
    
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        NetworkInterface iface;
        iface.name = d->name;
        iface.description = d->description ? d->description : "";
        
        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                iface.ip_addr = IpToString(a->addr);
                if (a->netmask) {
                    iface.subnet_mask = IpToString(a->netmask);
                }
                break;
            }
        }
        
        iface.mac_addr = GetMacAddress(iface.name);
        interfaces.push_back(iface);
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

std::string NetworkInterfaceManager::GetMacAddress(const std::string& adapter_name) {
    IP_ADAPTER_INFO* pAdapterInfo = nullptr;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == nullptr) {
        return "";
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (pAdapterInfo == nullptr) {
            return "";
        }
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        for (IP_ADAPTER_INFO* pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
            if (adapter_name.find(pAdapter->AdapterName) != std::string::npos) {
                std::string mac = MacToString(pAdapter->Address);
                free(pAdapterInfo);
                return mac;
            }
        }
    }
    
    free(pAdapterInfo);
    return "";
}

std::string NetworkInterfaceManager::IpToString(const sockaddr* addr) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
    return std::string(ip_str);
}

std::string NetworkInterfaceManager::MacToString(const unsigned char* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(mac[i]);
        if (i < 5) ss << ":";
    }
    return ss.str();
}