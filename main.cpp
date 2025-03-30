#define UNICODE
#define _UNICODE

#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <commctrl.h>
#include <pcap.h>
#include <string>
#include <vector>
#include <regex>
#include <fstream>
#include <thread>
#include <mutex>
#include "network_interface.h"
#include <condition_variable>
#include <chrono>

/**
 * 网络流量分析工具 - 主程序
 * 基于WinPcap/Npcap库和Windows API实现
 */

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

// 资源ID定义
#define IDC_START_BTN      1001
#define IDC_STOP_BTN       1002
#define IDC_SAVE_BTN       1003
#define IDC_FILTER_EDIT    1004
#define IDC_PACKET_LIST    1005
#define IDC_PACKET_DETAIL  1006
#define IDC_ATTACK_LOG     1007
#define IDC_ADAPTER_COMBO  1008
#define IDC_IP_FILTER_EDIT 1009
#define IDC_OPEN_BTN       1010

// 全局变量
HWND g_hWnd = NULL;
HWND g_hStartBtn = NULL;
HWND g_hStopBtn = NULL;
HWND g_hSaveBtn = NULL;
HWND g_hOpenBtn = NULL;
HWND g_hFilterEdit = NULL;
HWND g_hIPFilterEdit = NULL;
HWND g_hPacketList = NULL;
HWND g_hPacketDetail = NULL;
HWND g_hAttackLog = NULL;
HWND g_hAdapterCombo = NULL;
HWND g_hFilterLabel = NULL;
HWND g_hFilterTipLabel = NULL;
HWND g_hIPFilterLabel = NULL;
HWND g_hIPFilterTipLabel = NULL;
pcap_t* g_adhandle = NULL;
std::thread g_captureThread;
// bool g_isCapturing = false;
 std::mutex g_adhandleMutex;  // 保护 g_adhandle 的访问
std::atomic<bool> g_isCapturing(false);
std::mutex g_packetsMutex;
std::condition_variable g_cv;
std::vector<std::vector<u_char>> g_packets;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_if_t* alldevs;
pcap_if_t* d;
std::string g_ipFilter;

// 协议头定义
#pragma pack(push, 1)
struct ETHERNET_HEADER {
    BYTE dst_mac[6];
    BYTE src_mac[6];
    USHORT type;
};

struct IP_HEADER {
    BYTE ver_ihl;        // 版本和首部长度
    BYTE tos;            // 服务类型
    USHORT total_length; // 总长度
    USHORT id;           // 标识
    USHORT flags_offset; // 标志和片偏移
    BYTE ttl;            // 生存时间
    BYTE protocol;       // 协议
    USHORT checksum;     // 首部校验和
    ULONG src_addr;      // 源IP地址
    ULONG dst_addr;      // 目的IP地址
};

struct TCP_HEADER {
    USHORT src_port;       // 源端口
    USHORT dst_port;       // 目的端口
    ULONG seq_num;         // 序列号
    ULONG ack_num;         // 确认号
    BYTE data_offset;      // 数据偏移
    BYTE flags;            // 标志位
    USHORT window;         // 窗口大小
    USHORT checksum;       // 校验和
    USHORT urgent_ptr;     // 紧急指针
};

struct PacketInfo {
    SYSTEMTIME timestamp;
    char src_ip[16];
    char dst_ip[16];
    USHORT src_port;
    USHORT dst_port;
    USHORT protocol;
    ULONG payload_len;
    std::vector<u_char> raw_data;
};

// 文件存储格式
struct FileHeader {
    DWORD magic;     // 文件标识 0x504B5453
    DWORD version;   // 文件版本
    DWORD count;     // 数据包数量
};

struct PacketRecord {
    SYSTEMTIME timestamp;
    DWORD src_ip;
    DWORD dst_ip;
    WORD src_port;
    WORD dst_port;
    DWORD payload_len;
};
#pragma pack(pop)

// 函数声明
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateControls(HWND hWnd);
void StartCapture();
void StopCapture();
void SavePackets();
void ProcessPacket(const u_char* pkt_data, struct pcap_pkthdr* header);
void UpdatePacketList(const PacketInfo& info);
void ShowPacketDetail(int index);
bool DetectSQLInjection(const std::string& payload);
void LogAttack(const char* message);
void LogAttackW(const wchar_t* message);
void CheckSQLInjection();
void OpenPcapFile();

// 新增函数声明
std::string URLDecode(const std::string& encoded);
std::vector<std::string> SplitMultipartData(const std::string& data, const std::string& boundary);

// 主函数
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 初始化Common Controls
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);
    
    // 设置控件字体
    NONCLIENTMETRICSW ncm;
    ncm.cbSize = sizeof(NONCLIENTMETRICSW);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &ncm, 0);
    HFONT hFont = CreateFontIndirectW(&ncm.lfMessageFont);
    
    // 初始化WinSock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // 注册窗口类
    WNDCLASSEXW wcex;
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"NetworkAnalyzerClass";
    wcex.hIconSm = LoadIconW(NULL, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wcex)) {
        MessageBoxW(NULL, L"窗口注册失败", L"错误", MB_ICONERROR);
        return 1;
    }
    
    // 初始化应用程序实例
    if (!InitInstance(hInstance, nCmdShow)) {
        return 1;
    }
    
    // 消息循环
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    
    // 清理资源
    WSACleanup();
    return (int)msg.wParam;
}

// 初始化应用程序实例
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    g_hWnd = CreateWindowW(
        L"NetworkAnalyzerClass",
        L"网络流量分析工具 - 数据包监听与分析",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 1024, 768,  // 更大的窗口尺寸
        NULL, NULL, hInstance, NULL);
    
    if (!g_hWnd) {
        return FALSE;
    }
    
    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);
    
    return TRUE;
}

// 窗口过程函数
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            CreateControls(hWnd);
            break;
        case WM_COMMAND:
        switch (LOWORD(wParam)) {
            case IDC_START_BTN:
                StartCapture();
                EnableWindow(g_hStartBtn, FALSE);
                EnableWindow(g_hStopBtn, TRUE);
                break;
            case IDC_STOP_BTN:
                StopCapture();
                EnableWindow(g_hStartBtn, TRUE);
                EnableWindow(g_hStopBtn, FALSE);
                break;
                case IDC_SAVE_BTN:
                    // SQL注入检测按钮
                    CheckSQLInjection();
                    break;
                case IDC_OPEN_BTN:
                    // 打开PCAP文件按钮
                    OpenPcapFile();
                break;
        }
        break;
        case WM_NOTIFY:
            if (((LPNMHDR)lParam)->idFrom == IDC_PACKET_LIST && 
                ((LPNMHDR)lParam)->code == NM_CLICK) {
                NMITEMACTIVATE* item = (NMITEMACTIVATE*)lParam;
                ShowPacketDetail(item->iItem);
            }
            break;
        case WM_APP:
            // 如果已经开始捕获，则启用SQL注入分析按钮，但不修改其当前状态
            if (g_isCapturing) {
                EnableWindow(g_hSaveBtn, TRUE);
            }
            UpdatePacketList(*(PacketInfo*)lParam);
            break; 
        case WM_APP + 1:
            EnableWindow(g_hStartBtn, TRUE);
            EnableWindow(g_hStopBtn, FALSE);
            break;
        case WM_SIZE:
            if (g_hFilterEdit && g_hStartBtn && g_hStopBtn && g_hSaveBtn && 
                g_hPacketList && g_hPacketDetail && g_hAttackLog && g_hAdapterCombo && g_hIPFilterEdit) {
                RECT rc;
                GetClientRect(hWnd, &rc);
                
                // 顶部控件
                MoveWindow(g_hAdapterCombo, 10, 10, 300, 300, TRUE);  // 增加高度确保下拉框可见
                MoveWindow(g_hStartBtn, 320, 10, 80, 25, TRUE);
                MoveWindow(g_hStopBtn, 410, 10, 80, 25, TRUE);
                MoveWindow(g_hSaveBtn, 500, 10, 85, 25, TRUE);
                MoveWindow(g_hOpenBtn, rc.right - 140, 10, 120, 25, TRUE);  // 放在右侧位置
                
                // 过滤器标签和输入框
                MoveWindow(g_hFilterLabel, 10, 45, 100, 20, TRUE);
                MoveWindow(g_hFilterEdit, 120, 45, 190, 25, TRUE);
                MoveWindow(g_hFilterTipLabel, 320, 45, 250, 20, TRUE);
                
                MoveWindow(g_hIPFilterLabel, 10, 80, 100, 20, TRUE);
                MoveWindow(g_hIPFilterEdit, 120, 80, 190, 25, TRUE);
                MoveWindow(g_hIPFilterTipLabel, 320, 80, 250, 20, TRUE);
                
                // 数据包列表
                MoveWindow(g_hPacketList, 10, 115, rc.right - 20, (rc.bottom - 125) / 2, TRUE);
                
                // 数据包详情和日志面板
                int detailTop = 125 + (rc.bottom - 125) / 2;
                MoveWindow(g_hPacketDetail, 10, detailTop, rc.right - 20, (rc.bottom - 125) / 2 - 60, TRUE);
                MoveWindow(g_hAttackLog, 10, rc.bottom - 60, rc.right - 20, 50, TRUE);
            }
            break;
        case WM_DESTROY:
            if (g_isCapturing) {
                StopCapture();
            }
            if (g_captureThread.joinable()) {
                g_captureThread.join();
            }
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hWnd, message, wParam, lParam);
    }
    return 0;
}

// 创建控件
void CreateControls(HWND hWnd) {
    RECT rc;
    GetClientRect(hWnd, &rc);
    
    // 创建网卡选择下拉框
    g_hAdapterCombo = CreateWindowW(
        WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWN | CBS_HASSTRINGS,
        10, 10, 300, 300,  // 增加高度以确保下拉框可见
        hWnd, (HMENU)IDC_ADAPTER_COMBO, NULL, NULL
    );
    
    auto interfaces = NetworkInterfaceManager::GetAllInterfaces();
    for (const auto& iface : interfaces) {
        std::wstring description = 
            std::wstring(iface.description.begin(), iface.description.end()) + 
            L" [" + std::wstring(iface.ip_addr.begin(), iface.ip_addr.end()) + L"]";
        
        SendMessageW(g_hAdapterCombo, CB_ADDSTRING, 0, (LPARAM)description.c_str());
    }

    if (!interfaces.empty()) {
        SendMessageW(g_hAdapterCombo, CB_SETCURSEL, 0, 0);
    }

    g_hFilterLabel = CreateWindowW(
        L"STATIC", L"BPF过滤表达式:",
        WS_CHILD | WS_VISIBLE,
        10, 45, 100, 20,
        hWnd, NULL, NULL, NULL
    );
    
    g_hFilterEdit = CreateWindowW(
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        120, 45, 190, 25,
        hWnd, (HMENU)IDC_FILTER_EDIT, NULL, NULL
    );
    
    SetWindowTextW(g_hFilterEdit, L"ip");
    
    g_hFilterTipLabel = CreateWindowW(
        L"STATIC", L"例如: host 192.168.1.1 或 tcp port 80",
        WS_CHILD | WS_VISIBLE,
        320, 45, 250, 20,
        hWnd, NULL, NULL, NULL
    );
    
    g_hIPFilterLabel = CreateWindowW(
        L"STATIC", L"IP监听过滤:",
        WS_CHILD | WS_VISIBLE,
        10, 80, 100, 20,
        hWnd, NULL, NULL, NULL
    );
    
    g_hIPFilterEdit = CreateWindowW(
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        120, 80, 190, 25,
        hWnd, (HMENU)IDC_IP_FILTER_EDIT, NULL, NULL
    );
    
    g_hIPFilterTipLabel = CreateWindowW(
        L"STATIC", L"输入要监听的IP地址，留空监听所有IP",
        WS_CHILD | WS_VISIBLE,
        320, 80, 250, 20,
        hWnd, NULL, NULL, NULL
    );
    
    g_hStartBtn = CreateWindowW(
        L"BUTTON", L"开始抓包",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        320, 10, 80, 25,  // 恢复原来的位置
        hWnd, (HMENU)IDC_START_BTN, NULL, NULL
    );
    
    g_hStopBtn = CreateWindowW(
        L"BUTTON", L"停止抓包",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        410, 10, 80, 25,  // 恢复原来的位置
        hWnd, (HMENU)IDC_STOP_BTN, NULL, NULL
    );
    
    g_hSaveBtn = CreateWindowW(
        L"BUTTON", L"分析SQL注入",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        500, 10, 85, 25,  // 稍微增加宽度以适应新文本
        hWnd, (HMENU)IDC_SAVE_BTN, NULL, NULL
    );
    
    g_hPacketList = CreateWindowW(
        WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS,
        10, 115, rc.right - 20, (rc.bottom - 125) / 2,  // 调整列表位置
        hWnd, (HMENU)IDC_PACKET_LIST, NULL, NULL
    );
    
    ListView_SetExtendedListViewStyle(g_hPacketList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    g_hPacketDetail = CreateWindowW(
        WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS,
        10, 125 + (rc.bottom - 125) / 2, rc.right - 20, (rc.bottom - 125) / 2 - 60,  // 调整详情位置
        hWnd, (HMENU)IDC_PACKET_DETAIL, NULL, NULL
    );
    
    // 创建数据包列表的列
    LVCOLUMNW lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = const_cast<LPWSTR>(L"序号");
    lvc.cx = 50;
    ListView_InsertColumn(g_hPacketList, 0, &lvc);
    
    lvc.pszText = const_cast<LPWSTR>(L"时间");
    lvc.cx = 100;
    ListView_InsertColumn(g_hPacketList, 1, &lvc);
    
    lvc.pszText = const_cast<LPWSTR>(L"源IP");
    lvc.cx = 120;
    ListView_InsertColumn(g_hPacketList, 2, &lvc);
    
    lvc.pszText = const_cast<LPWSTR>(L"目的IP");
    lvc.cx = 120;
    ListView_InsertColumn(g_hPacketList, 3, &lvc);
    
    lvc.pszText = const_cast<LPWSTR>(L"源端口");
    lvc.cx = 70;
    ListView_InsertColumn(g_hPacketList, 4, &lvc);
    
    lvc.pszText = const_cast<LPWSTR>(L"目的端口");
    lvc.cx = 70;
    ListView_InsertColumn(g_hPacketList, 5, &lvc);
    
    lvc.pszText = const_cast<LPWSTR>(L"协议");
    lvc.cx = 50;
    ListView_InsertColumn(g_hPacketList, 6, &lvc);
    
    lvc.pszText = const_cast<LPWSTR>(L"长度");
    lvc.cx = 70;
    ListView_InsertColumn(g_hPacketList, 7, &lvc);
    
    g_hAttackLog = CreateWindowW(
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
        10, rc.bottom - 60, rc.right - 20, 50,  // 调整日志位置
        hWnd, (HMENU)IDC_ATTACK_LOG, NULL, NULL
    );

    // 创建打开文件按钮
    g_hOpenBtn = CreateWindowW(
        L"BUTTON", L"打开PCAP文件",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        800, 10, 120, 25,
        hWnd, (HMENU)IDC_OPEN_BTN, NULL, NULL
    );
    
    // 初始化按钮状态
    EnableWindow(g_hStartBtn, TRUE);
    EnableWindow(g_hStopBtn, FALSE);
    EnableWindow(g_hSaveBtn, FALSE);
    EnableWindow(g_hOpenBtn, TRUE);
}

void StartCapture() {
    if (g_isCapturing) {
        MessageBoxW(g_hWnd, L"已经在抓包中", L"提示", MB_ICONINFORMATION);
        return;
    }

    int selected_index = SendMessage(g_hAdapterCombo, CB_GETCURSEL, 0, 0);
    if (selected_index == CB_ERR) {
        MessageBoxW(g_hWnd, L"请选择网卡", L"错误", MB_ICONERROR);
        return;
    }

    auto interfaces = NetworkInterfaceManager::GetAllInterfaces();
    if (interfaces.empty()) {
        MessageBoxW(g_hWnd, L"未找到可用网卡", L"错误", MB_ICONERROR);
        return;
    }

    if (selected_index >= interfaces.size()) {
        MessageBoxW(g_hWnd, L"网卡选择无效", L"错误", MB_ICONERROR);
        return;
    }

    auto& selected_iface = interfaces[selected_index];

    if (selected_iface.name.empty() || selected_iface.ip_addr.empty()) {
        MessageBoxW(g_hWnd, L"所选网卡状态异常", L"错误", MB_ICONERROR);
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    {
        std::lock_guard<std::mutex> lock(g_adhandleMutex);
        g_adhandle = pcap_open(selected_iface.name.c_str(),
                               65536,
                               PCAP_OPENFLAG_PROMISCUOUS,
                               1000,
                               NULL,
                               errbuf);
    }

    if (g_adhandle == NULL) {
        std::wstring error_msg = L"无法打开网卡: ";
        std::wstring werrbuf;
        werrbuf.assign(errbuf, errbuf + strlen(errbuf));
        error_msg += werrbuf;
        MessageBoxW(g_hWnd, error_msg.c_str(), L"错误", MB_ICONERROR);
        return;
    }

    WCHAR wip_filter[256] = {0};
    GetWindowTextW(g_hIPFilterEdit, wip_filter, 256);
    char ip_filter[256] = {0};
    WideCharToMultiByte(CP_ACP, 0, wip_filter, -1, ip_filter, 256, NULL, NULL);
    g_ipFilter = ip_filter;

    WCHAR wfilter[256] = {0};
    GetWindowTextW(g_hFilterEdit, wfilter, 256);
    char filter[512] = {0};
    WideCharToMultiByte(CP_ACP, 0, wfilter, -1, filter, 256, NULL, NULL);

    if (strlen(filter) == 0) {
        strcpy_s(filter, "ip");
    }

    if (strlen(ip_filter) > 0) {
        char combined_filter[512] = {0};
        sprintf_s(combined_filter, "(%s) and (src host %s or dst host %s)", 
                 filter, ip_filter, ip_filter);
        strcpy_s(filter, combined_filter);
    }

    struct bpf_program fcode;
    if (pcap_compile(g_adhandle, &fcode, filter, 1, 0) < 0) {
        MessageBoxW(g_hWnd, L"无法编译过滤器", L"错误", MB_ICONERROR);
        pcap_close(g_adhandle);
        g_adhandle = NULL;
        return;
    }

    if (pcap_setfilter(g_adhandle, &fcode) < 0) {
        MessageBoxW(g_hWnd, L"无法设置过滤器", L"错误", MB_ICONERROR);
        pcap_close(g_adhandle);
        g_adhandle = NULL;
        return;
    }

    // 启动抓包线程
    g_isCapturing = true;
    g_captureThread = std::thread([&]() {
        while (g_isCapturing) {
            pcap_pkthdr* header;
            const u_char* pkt_data;
            int res;

            { 
                std::lock_guard<std::mutex> lock(g_adhandleMutex);
                if (!g_isCapturing || !g_adhandle) break;  // 及时退出
                res = pcap_next_ex(g_adhandle, &header, &pkt_data);
            }

            if (res == 1) {
                ProcessPacket(pkt_data, header);
            } else if (res == -1) {  // 错误
                break;
            } else if (res == -2) {  // 被中断
                break;
            }
            // res=0 超时，继续循环
        }

        { 
            std::lock_guard<std::mutex> lock(g_adhandleMutex);
            if (g_adhandle) {
                pcap_close(g_adhandle);
                g_adhandle = nullptr;
            }
        }
    });

    // 更新UI状态
    EnableWindow(g_hStartBtn, FALSE);
    EnableWindow(g_hStopBtn, TRUE);
    EnableWindow(g_hSaveBtn, TRUE);  // 使SQL注入检查按钮在开始捕获后可用
    EnableWindow(g_hOpenBtn, FALSE); // 捕获时禁用打开文件按钮

    // 显示开始抓包提示
    std::wstring status = L"开始抓包...\n选中网卡: " + 
                         std::wstring(selected_iface.description.begin(), selected_iface.description.end()) +
                         L"\nIP地址: " + std::wstring(selected_iface.ip_addr.begin(), selected_iface.ip_addr.end());
    
    if (!g_ipFilter.empty()) {
        status += L"\n过滤监听IP: " + std::wstring(g_ipFilter.begin(), g_ipFilter.end());
    } else {
        status += L"\n监听所有IP地址";
    }
    
    SetWindowTextW(g_hAttackLog, status.c_str());
}

void StopCapture() {
    { 
        std::lock_guard<std::mutex> lock(g_adhandleMutex);
        if (g_isCapturing) {
            g_isCapturing = false;
            if (g_adhandle) {
                pcap_breakloop(g_adhandle);  // 强制中断抓包循环
            }
        }
    }

    if (g_captureThread.joinable()) {
        // 设置超时时间（例如 2 秒）
        auto timeout = std::chrono::seconds(2);
        auto startTime = std::chrono::steady_clock::now();

        // 等待线程退出
        while (g_captureThread.joinable()) {
            if (std::chrono::steady_clock::now() - startTime > timeout) {
                // 超时后强制关闭抓包句柄
                std::lock_guard<std::mutex> lock(g_adhandleMutex);
                if (g_adhandle) {
                    pcap_close(g_adhandle);
                    g_adhandle = nullptr;
                }
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));  // 避免忙等待
        }

        // 如果线程仍未退出，则强制分离线程
        if (g_captureThread.joinable()) {
            g_captureThread.detach();
        }
    }

    // 直接更新UI状态（主线程中执行）
    EnableWindow(g_hStartBtn, TRUE);
    EnableWindow(g_hStopBtn, FALSE);
    EnableWindow(g_hOpenBtn, TRUE);  // 确保打开文件按钮启用
    // 保持g_hSaveBtn可用，不禁用SQL注入检查按钮
    
    // 询问用户是否保存数据包
    if (!g_packets.empty()) {
        int result = MessageBoxW(g_hWnd, L"是否保存已捕获的数据包？", L"保存确认", MB_YESNO | MB_ICONQUESTION);
        if (result == IDYES) {
            SavePackets();
        }
    }
}

void ProcessPacket(const u_char* pkt_data, struct pcap_pkthdr* header) {
    // 创建数据包信息结构
    PacketInfo info;
    GetSystemTime(&info.timestamp);
    
    // 保存原始数据包
    info.raw_data.assign(pkt_data, pkt_data + header->len);
    
    // 解析以太网帧头
    ETHERNET_HEADER* eth_header = (ETHERNET_HEADER*)pkt_data;
    
    // 检查是否是IP数据包 (0x0800)
    if (ntohs(eth_header->type) != 0x0800) {
        info.protocol = 0;
        info.payload_len = header->len;
        strcpy_s(info.src_ip, "非IP数据包");
        strcpy_s(info.dst_ip, "非IP数据包");
        info.src_port = 0;
        info.dst_port = 0;
        SendMessage(g_hWnd, WM_APP, 0, (LPARAM)&info);
        std::lock_guard<std::mutex> lock(g_packetsMutex);
        g_packets.push_back(info.raw_data);
        return;
    }
    
    // 解析IP头
    IP_HEADER* ip_header = (IP_HEADER*)(pkt_data + sizeof(ETHERNET_HEADER));
    int ip_header_len = (ip_header->ver_ihl & 0x0F) * 4;
    
    // 转换IP地址为字符串
    sprintf(info.src_ip, "%d.%d.%d.%d", 
            (ip_header->src_addr) & 0xFF,
            (ip_header->src_addr >> 8) & 0xFF,
            (ip_header->src_addr >> 16) & 0xFF,
            (ip_header->src_addr >> 24) & 0xFF);
    
    sprintf(info.dst_ip, "%d.%d.%d.%d", 
            (ip_header->dst_addr) & 0xFF,
            (ip_header->dst_addr >> 8) & 0xFF,
            (ip_header->dst_addr >> 16) & 0xFF,
            (ip_header->dst_addr >> 24) & 0xFF);
    
    // 获取协议类型
    info.protocol = ip_header->protocol;
    
    // 解析TCP/UDP/ICMP等头部
    switch (ip_header->protocol) {
        case 6: { // TCP协议
        TCP_HEADER* tcp_header = (TCP_HEADER*)(pkt_data + sizeof(ETHERNET_HEADER) + ip_header_len);
        info.src_port = ntohs(tcp_header->src_port);
        info.dst_port = ntohs(tcp_header->dst_port);
            break;
        }
        case 17: { // UDP协议
            struct UDP_HEADER {
                USHORT src_port;
                USHORT dst_port;
                USHORT length;
                USHORT checksum;
            };
            UDP_HEADER* udp_header = (UDP_HEADER*)(pkt_data + sizeof(ETHERNET_HEADER) + ip_header_len);
            info.src_port = ntohs(udp_header->src_port);
            info.dst_port = ntohs(udp_header->dst_port);
            break;
        }
        default:
        info.src_port = 0;
        info.dst_port = 0;
            break;
    }
    
    info.payload_len = header->len;
    
    // 更新UI
    UpdatePacketList(info);
    
    // 保存数据包
    std::lock_guard<std::mutex> lock(g_packetsMutex);
    g_packets.push_back(info.raw_data);
}

void UpdatePacketList(const PacketInfo& info) {
    // 获取当前列表项数量
    int count = ListView_GetItemCount(g_hPacketList);
    
    // 添加新项
    LVITEMW lvi = {0};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = count;
    
    // 序号
    wchar_t buffer[256];
    swprintf(buffer, L"%d", count + 1);
    lvi.iSubItem = 0;
    lvi.pszText = buffer;
    ListView_InsertItem(g_hPacketList, &lvi);
    
    // 时间
    swprintf(buffer, L"%02d:%02d:%02d.%03d", 
            info.timestamp.wHour, info.timestamp.wMinute, 
            info.timestamp.wSecond, info.timestamp.wMilliseconds);
    lvi.iSubItem = 1;
    lvi.pszText = buffer;
    ListView_SetItem(g_hPacketList, &lvi);
    
    // 源IP
    wchar_t wstr_src_ip[16];
    mbstowcs(wstr_src_ip, info.src_ip, 16);
    lvi.iSubItem = 2;
    lvi.pszText = wstr_src_ip;
    ListView_SetItem(g_hPacketList, &lvi);
    
    // 目的IP
    wchar_t wstr_dst_ip[16];
    mbstowcs(wstr_dst_ip, info.dst_ip, 16);
    lvi.iSubItem = 3;
    lvi.pszText = wstr_dst_ip;
    ListView_SetItem(g_hPacketList, &lvi);
    
    // 源端口
    swprintf(buffer, L"%d", info.src_port);
    lvi.iSubItem = 4;
    lvi.pszText = buffer;
    ListView_SetItem(g_hPacketList, &lvi);
    
    // 目的端口
    swprintf(buffer, L"%d", info.dst_port);
    lvi.iSubItem = 5;
    lvi.pszText = buffer;
    ListView_SetItem(g_hPacketList, &lvi);
    
    // 协议
    lvi.iSubItem = 6;
    const wchar_t* protocol_name = L"未知";
    switch (info.protocol) {
        case 1: protocol_name = L"ICMP"; break;
        case 2: protocol_name = L"IGMP"; break;
        case 6: protocol_name = L"TCP"; break;
        case 17: protocol_name = L"UDP"; break;
        case 47: protocol_name = L"GRE"; break;
        case 50: protocol_name = L"ESP"; break;
        case 51: protocol_name = L"AH"; break;
        case 89: protocol_name = L"OSPF"; break;
    }
    lvi.pszText = const_cast<LPWSTR>(protocol_name);
    ListView_SetItem(g_hPacketList, &lvi);
    
    // 长度
    swprintf(buffer, L"%d", info.payload_len);
    lvi.iSubItem = 7;
    lvi.pszText = buffer;
    ListView_SetItem(g_hPacketList, &lvi);
    
    // 滚动到最新项
    ListView_EnsureVisible(g_hPacketList, count, FALSE);
}

void ShowPacketDetail(int index) {
    if (index < 0 || index >= g_packets.size()) return;
    
    // 清空树视图
    TreeView_DeleteAllItems(g_hPacketDetail);
    
    // 获取数据包
    std::vector<u_char> packet;
    {
        std::lock_guard<std::mutex> lock(g_packetsMutex);
        packet = g_packets[index];
    }
    
    // 解析以太网帧头
    ETHERNET_HEADER* eth_header = (ETHERNET_HEADER*)packet.data();
    
    // 添加以太网帧头信息
    TVINSERTSTRUCTW tvis = {0};
    tvis.hParent = NULL;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_CHILDREN;
    tvis.item.pszText = const_cast<LPWSTR>(L"以太网帧");
    tvis.item.cChildren = 1;
    HTREEITEM hEthernet = TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // 添加MAC地址信息
    wchar_t buffer[256];
    tvis.hParent = hEthernet;
    tvis.item.cChildren = 0;
    
    swprintf(buffer, L"源MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
            eth_header->src_mac[0], eth_header->src_mac[1], eth_header->src_mac[2],
            eth_header->src_mac[3], eth_header->src_mac[4], eth_header->src_mac[5]);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"目的MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
            eth_header->dst_mac[0], eth_header->dst_mac[1], eth_header->dst_mac[2],
            eth_header->dst_mac[3], eth_header->dst_mac[4], eth_header->dst_mac[5]);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"类型: 0x%04X", ntohs(eth_header->type));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // 检查是否是IP数据包
    if (ntohs(eth_header->type) != 0x0800) return;
    
    // 解析IP头
    IP_HEADER* ip_header = (IP_HEADER*)(packet.data() + sizeof(ETHERNET_HEADER));
    int ip_header_len = (ip_header->ver_ihl & 0x0F) * 4;
    
    // 添加IP头信息
    tvis.hParent = NULL;
    tvis.item.cChildren = 1;
    tvis.item.pszText = const_cast<LPWSTR>(L"IP头");
    HTREEITEM hIP = TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    tvis.hParent = hIP;
    tvis.item.cChildren = 0;
    
    // 显示更完整的IP首部信息
    swprintf(buffer, L"版本: %d", (ip_header->ver_ihl >> 4) & 0x0F);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"首部长度: %d 字节", ip_header_len);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"服务类型(TOS): 0x%02X", ip_header->tos);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"总长度: %d 字节", ntohs(ip_header->total_length));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"标识: 0x%04X", ntohs(ip_header->id));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // 解析标志位和片偏移
    USHORT flags_offset = ntohs(ip_header->flags_offset);
    BYTE flags = (flags_offset >> 13) & 0x07;
    USHORT offset = flags_offset & 0x1FFF;
    
    swprintf(buffer, L"标志: %s%s%s (0x%X)", 
             (flags & 0x04) ? L"保留 " : L"",
             (flags & 0x02) ? L"DF " : L"",
             (flags & 0x01) ? L"MF " : L"",
             flags);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"片偏移: %d", offset);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"生存时间(TTL): %d", ip_header->ttl);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // 解析协议字段
    const wchar_t* protocol_name = L"未知";
    switch (ip_header->protocol) {
        case 1: protocol_name = L"ICMP"; break;
        case 2: protocol_name = L"IGMP"; break;
        case 6: protocol_name = L"TCP"; break;
        case 17: protocol_name = L"UDP"; break;
        case 47: protocol_name = L"GRE"; break;
        case 50: protocol_name = L"ESP"; break;
        case 51: protocol_name = L"AH"; break;
        case 89: protocol_name = L"OSPF"; break;
    }
    
    swprintf(buffer, L"协议: %d (%s)", ip_header->protocol, protocol_name);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"首部校验和: 0x%04X", ntohs(ip_header->checksum));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"源IP: %d.%d.%d.%d", 
            (ip_header->src_addr) & 0xFF,
            (ip_header->src_addr >> 8) & 0xFF,
            (ip_header->src_addr >> 16) & 0xFF,
            (ip_header->src_addr >> 24) & 0xFF);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"目的IP: %d.%d.%d.%d", 
            (ip_header->dst_addr) & 0xFF,
            (ip_header->dst_addr >> 8) & 0xFF,
            (ip_header->dst_addr >> 16) & 0xFF,
            (ip_header->dst_addr >> 24) & 0xFF);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // 检查是否是TCP数据包
    if (ip_header->protocol != 6) return;
    
    // 解析TCP头
    TCP_HEADER* tcp_header = (TCP_HEADER*)(packet.data() + sizeof(ETHERNET_HEADER) + ip_header_len);
    int tcp_header_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
    
    // 添加TCP头信息
    tvis.hParent = NULL;
    tvis.item.cChildren = 1;
    tvis.item.pszText = const_cast<LPWSTR>(L"TCP头");
    HTREEITEM hTCP = TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    tvis.hParent = hTCP;
    tvis.item.cChildren = 0;
    
    swprintf(buffer, L"源端口: %d", ntohs(tcp_header->src_port));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"目的端口: %d", ntohs(tcp_header->dst_port));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"序列号: %u", ntohl(tcp_header->seq_num));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"确认号: %u", ntohl(tcp_header->ack_num));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"首部长度: %d 字节", tcp_header_len);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // TCP标志位详细展示
    BYTE tcp_flags = tcp_header->flags;
    swprintf(buffer, L"标志位: 0x%02X", tcp_flags);
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // 单独列出每个标志位
    if (tcp_flags & 0x20) {
        tvis.item.pszText = const_cast<LPWSTR>(L"-- URG: 1 (紧急指针有效)");
        TreeView_InsertItem(g_hPacketDetail, &tvis);
    }
    if (tcp_flags & 0x10) {
        tvis.item.pszText = const_cast<LPWSTR>(L"-- ACK: 1 (确认号有效)");
        TreeView_InsertItem(g_hPacketDetail, &tvis);
    }
    if (tcp_flags & 0x08) {
        tvis.item.pszText = const_cast<LPWSTR>(L"-- PSH: 1 (接收方应尽快将数据交给应用层)");
        TreeView_InsertItem(g_hPacketDetail, &tvis);
    }
    if (tcp_flags & 0x04) {
        tvis.item.pszText = const_cast<LPWSTR>(L"-- RST: 1 (复位连接)");
        TreeView_InsertItem(g_hPacketDetail, &tvis);
    }
    if (tcp_flags & 0x02) {
        tvis.item.pszText = const_cast<LPWSTR>(L"-- SYN: 1 (建立连接)");
        TreeView_InsertItem(g_hPacketDetail, &tvis);
    }
    if (tcp_flags & 0x01) {
        tvis.item.pszText = const_cast<LPWSTR>(L"-- FIN: 1 (发送方完成发送任务)");
        TreeView_InsertItem(g_hPacketDetail, &tvis);
    }
    
    swprintf(buffer, L"窗口大小: %d", ntohs(tcp_header->window));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"校验和: 0x%04X", ntohs(tcp_header->checksum));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    swprintf(buffer, L"紧急指针: 0x%04X", ntohs(tcp_header->urgent_ptr));
    tvis.item.pszText = buffer;
    TreeView_InsertItem(g_hPacketDetail, &tvis);
    
    // 添加数据负载信息
    int payload_offset = sizeof(ETHERNET_HEADER) + ip_header_len + tcp_header_len;
    int payload_len = packet.size() - payload_offset;
    
    if (payload_len > 0) {
        tvis.hParent = NULL;
        tvis.item.cChildren = 1;
        swprintf(buffer, L"数据负载 (%d 字节)", payload_len);
        tvis.item.pszText = buffer;
        HTREEITEM hPayload = TreeView_InsertItem(g_hPacketDetail, &tvis);
        
        // 以十六进制显示负载数据
        const int BYTES_PER_LINE = 16;
        for (int i = 0; i < payload_len; i += BYTES_PER_LINE) {
            wchar_t hex[50] = {0};
            wchar_t ascii[20] = {0};
            int line_len = std::min(BYTES_PER_LINE, payload_len - i);
            
            // 生成十六进制显示
            int pos = 0;
            for (int j = 0; j < line_len; j++) {
                swprintf(hex + pos, 50 - pos, L"%02X ", packet[payload_offset + i + j]);
                pos += 3;
                
                // 生成ASCII显示
                BYTE ch = packet[payload_offset + i + j];
                ascii[j] = (ch >= 32 && ch <= 126) ? ch : '.';
            }
            
            // 合并十六进制和ASCII显示
            swprintf(buffer, L"%04X: %-48s  %s", i, hex, ascii);
            tvis.hParent = hPayload;
            tvis.item.pszText = buffer;
            TreeView_InsertItem(g_hPacketDetail, &tvis);
        }
    }
    
    // 展开所有节点
    TreeView_Expand(g_hPacketDetail, hEthernet, TVE_EXPAND);
    TreeView_Expand(g_hPacketDetail, hIP, TVE_EXPAND);
    TreeView_Expand(g_hPacketDetail, hTCP, TVE_EXPAND);
}

void SavePackets() {
    if (g_packets.empty()) return;

    // 创建保存文件对话框
    wchar_t filename[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"PCAP文件 (*.pcap)\0*.pcap\0所有文件 (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"pcap";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (!GetSaveFileNameW(&ofn)) return;

    // 转换宽字符文件名为多字节字符串
    char mbFilename[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, filename, -1, mbFilename, MAX_PATH, NULL, NULL);

    // 使用当前打开的网卡句柄创建转储文件
    pcap_dumper_t* dumper = nullptr;
    pcap_t* temp_handle = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(g_adhandleMutex);
        if (g_adhandle) {
            // 如果有活动的捕获句柄，使用它
            dumper = pcap_dump_open(g_adhandle, mbFilename);
        }
    }
    
    // 如果没有活动的捕获句柄，创建一个临时句柄
    if (!dumper) {
        // 获取选中的网卡
        int selected_index = SendMessage(g_hAdapterCombo, CB_GETCURSEL, 0, 0);
        if (selected_index != CB_ERR) {
            auto interfaces = NetworkInterfaceManager::GetAllInterfaces();
            if (!interfaces.empty() && selected_index < interfaces.size()) {
                auto& selected_iface = interfaces[selected_index];
                char errbuf[PCAP_ERRBUF_SIZE] = {0};
                
                // 打开网卡创建临时句柄
                temp_handle = pcap_open(selected_iface.name.c_str(),
                                       65536,
                                       PCAP_OPENFLAG_PROMISCUOUS,
                                       1000,
                                       NULL,
                                       errbuf);
                
                if (temp_handle) {
                    dumper = pcap_dump_open(temp_handle, mbFilename);
                }
            }
        }
        
        // 如果仍然无法创建dumper，使用默认的DLT_EN10MB
        if (!dumper) {
            temp_handle = pcap_open_dead(DLT_EN10MB, 65535);
            if (temp_handle) {
                dumper = pcap_dump_open(temp_handle, mbFilename);
            }
        }
    }

    if (!dumper) {
        MessageBoxW(g_hWnd, L"无法创建PCAP文件", L"错误", MB_ICONERROR);
        if (temp_handle) pcap_close(temp_handle);
        return;
    }

    // 写入数据包
    std::lock_guard<std::mutex> lock(g_packetsMutex);
    for (const auto& packet : g_packets) {
        // 构造PCAP数据包头
        struct pcap_pkthdr header;
        
        // 使用当前时间作为时间戳
        SYSTEMTIME st;
        GetSystemTime(&st);
        
        // 转换SYSTEMTIME为timeval
        FILETIME ft;
        SystemTimeToFileTime(&st, &ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        
        // 从1601年到1970年的100纳秒间隔数
        const ULONGLONG EPOCH_DIFFERENCE = 116444736000000000ULL;
        
        // 转换为Unix时间戳
        uli.QuadPart -= EPOCH_DIFFERENCE;
        header.ts.tv_sec = (long)(uli.QuadPart / 10000000);
        header.ts.tv_usec = (long)((uli.QuadPart % 10000000) / 10);
        
        header.caplen = packet.size();
        header.len = packet.size();
        
        // 使用pcap_dump写入数据包
        pcap_dump((u_char*)dumper, &header, packet.data());
    }

    // 关闭转储文件
    pcap_dump_close(dumper);
    
    // 关闭临时句柄
    if (temp_handle) {
        pcap_close(temp_handle);
    }

    MessageBoxW(g_hWnd, L"数据包保存成功", L"提示", MB_ICONINFORMATION);
}

bool DetectSQLInjection(const std::string& payload) {
    // 基本的SQL注入检测模式
    static const std::regex sql_patterns[] = {
        // 单引号注入和注释攻击
        std::regex("('|%27)[^\\w\\s]*(--|#|/\\*|;|%3B)", std::regex::icase),
        
        // 常见的SQL关键字攻击
        std::regex("\\b(union\\s+select|insert\\s+into|update\\s+set|delete\\s+from|drop\\s+table|alter\\s+table|exec(\\s+|\\+)+(s|x)p\\w+)\\b", std::regex::icase),
        
        // 堆叠查询攻击
        std::regex(";[\\s\\w]*?(select|insert|update|delete|drop|alter|exec)\\b", std::regex::icase),
        
        // 布尔盲注
        std::regex("\\band\\s+\\d+=\\d+\\b|\\bor\\s+\\d+=\\d+\\b|\\band\\s+'[^']+'='[^']+'\\b|\\bor\\s+'[^']+'='[^']+'\\b", std::regex::icase),
        
        // 时间盲注
        std::regex("\\b(sleep|waitfor\\s+delay|pg_sleep|benchmark)\\s*\\(", std::regex::icase),
        
        // 常见的绕过技术
        std::regex("(%27|\\')\\s*or\\s*1\\s*=\\s*1|\\bunion\\s+[^\\w]*(all|distinct|select)\\b", std::regex::icase)
    };

    // 检查是否是HTTP请求
    if (payload.find("GET ") == 0 || payload.find("POST ") == 0) {
        // 查找请求头和请求体的分界
        size_t header_end = payload.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            return false;
        }

        // 提取请求行和请求头
        std::string request_line = payload.substr(0, payload.find("\r\n"));
        std::string headers = payload.substr(payload.find("\r\n") + 2, header_end - payload.find("\r\n") - 2);
        std::string body = payload.substr(header_end + 4);

        // 分析GET请求
        if (request_line.find("GET ") == 0) {
            // 提取URL和查询参数
            size_t url_start = request_line.find(" ") + 1;
            size_t url_end = request_line.find(" ", url_start);
            if (url_end == std::string::npos) {
                return false;
            }
            std::string url = request_line.substr(url_start, url_end - url_start);

            // 提取查询参数
            size_t query_start = url.find("?");
            if (query_start != std::string::npos) {
                std::string query = url.substr(query_start + 1);
                // URL解码
                std::string decoded_query = URLDecode(query);
                
                // 检查查询参数
                for (const auto& pattern : sql_patterns) {
                    if (std::regex_search(decoded_query, pattern)) {
                        return true;
                    }
                }
            }
        }
        // 分析POST请求
        else if (request_line.find("POST ") == 0) {
            // 检查Content-Type
            std::string content_type;
            size_t ct_pos = headers.find("Content-Type: ");
            if (ct_pos != std::string::npos) {
                size_t ct_end = headers.find("\r\n", ct_pos);
                content_type = headers.substr(ct_pos + 13, ct_end - ct_pos - 13);
            }

            // 处理不同Content-Type的POST数据
            if (content_type == "application/x-www-form-urlencoded") {
                // URL解码POST数据
                std::string decoded_body = URLDecode(body);
                for (const auto& pattern : sql_patterns) {
                    if (std::regex_search(decoded_body, pattern)) {
                        return true;
                    }
                }
            }
            else if (content_type == "application/json") {
                // 处理JSON数据
                try {
                    // 这里可以添加JSON解析逻辑
                    // 目前简单检查整个JSON字符串
                    for (const auto& pattern : sql_patterns) {
                        if (std::regex_search(body, pattern)) {
                            return true;
                        }
                    }
                }
                catch (...) {
                    // JSON解析失败，跳过
                }
            }
            else if (content_type == "multipart/form-data") {
                // 处理multipart数据
                // 提取boundary
                size_t boundary_pos = content_type.find("boundary=");
                if (boundary_pos != std::string::npos) {
                    std::string boundary = content_type.substr(boundary_pos + 9);
                    // 解析multipart数据
                    std::vector<std::string> parts = SplitMultipartData(body, boundary);
                    for (const auto& part : parts) {
                        for (const auto& pattern : sql_patterns) {
                            if (std::regex_search(part, pattern)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
}

// URL解码函数
std::string URLDecode(const std::string& encoded) {
    std::string decoded;
    for (size_t i = 0; i < encoded.length(); ++i) {
        if (encoded[i] == '%') {
            if (i + 2 < encoded.length()) {
                int value;
                std::istringstream hex_chars(encoded.substr(i + 1, 2));
                hex_chars >> std::hex >> value;
                decoded += static_cast<char>(value);
                i += 2;
            }
        }
        else if (encoded[i] == '+') {
            decoded += ' ';
        }
        else {
            decoded += encoded[i];
        }
    }
    return decoded;
}

// 分割multipart数据
std::vector<std::string> SplitMultipartData(const std::string& data, const std::string& boundary) {
    std::vector<std::string> parts;
    std::string delimiter = "--" + boundary;
    size_t pos = 0;
    size_t prev = 0;

    while ((pos = data.find(delimiter, prev)) != std::string::npos) {
        if (pos > prev) {
            parts.push_back(data.substr(prev, pos - prev));
        }
        prev = pos + delimiter.length();
    }

    if (prev < data.length()) {
        parts.push_back(data.substr(prev));
    }

    return parts;
}

// 添加宽字符版本的日志函数
void LogAttackW(const wchar_t* wMessage) {
    // 获取当前时间
    SYSTEMTIME st;
    GetSystemTime(&st);
    
    // 格式化日志消息
    wchar_t wTimestamp[32];
    swprintf(wTimestamp, L"%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
    
    // 格式化Unicode日志消息
    wchar_t wLogEntry[512];
    swprintf(wLogEntry, L"[%s] %s\r\n", wTimestamp, wMessage);
    
    // 获取当前文本长度
    int textLength = GetWindowTextLengthW(g_hAttackLog);
    
    // 将光标移到文本末尾
    SendMessageW(g_hAttackLog, EM_SETSEL, (WPARAM)textLength, (LPARAM)textLength);
    
    // 插入新的日志消息
    SendMessageW(g_hAttackLog, EM_REPLACESEL, FALSE, (LPARAM)wLogEntry);
    
    // 自动滚动到最新的日志
    SendMessageW(g_hAttackLog, EM_SCROLLCARET, 0, 0);
}

void LogAttack(const char* message) {
    // 将ASCII/UTF-8消息转换为Unicode，尝试多种编码方式
    wchar_t wMessage[512] = {0};
    
    // 尝试UTF-8编码转换
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, message, -1, wMessage, 512) == 0) {
        // 如果UTF-8转换失败，尝试系统默认ANSI编码
        MultiByteToWideChar(CP_ACP, 0, message, -1, wMessage, 512);
    }
    
    // 调用宽字符版本
    LogAttackW(wMessage);
}

// 将二进制数据转换为可打印的十六进制格式
std::string BinaryToHexString(const unsigned char* data, size_t len) {
    static const char hex_chars[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(len * 3); // 每个字节需要两个十六进制字符和一个空格
    
    for (size_t i = 0; i < len; ++i) {
        unsigned char byte = data[i];
        result.push_back(hex_chars[(byte >> 4) & 0x0F]);
        result.push_back(hex_chars[byte & 0x0F]);
        result.push_back(' ');
    }
    
    return result;
}

// 安全地处理可能包含二进制数据的负载
std::string SafePayloadToString(const std::string& payload) {
    std::string result;
    result.reserve(payload.size());
    
    for (size_t i = 0; i < payload.size(); ++i) {
        char c = payload[i];
        // 只保留可打印ASCII字符，替换其他字符
        if (c >= 32 && c <= 126) {
            result.push_back(c);
        } else {
            result.push_back('.');
        }
    }
    
    return result;
}

void CheckSQLInjection() {
    if (g_packets.empty()) {
        MessageBoxW(g_hWnd, L"没有捕获的数据包可供分析", L"SQL注入检查", MB_ICONINFORMATION);
        return;
    }
    
    // 禁用SQL注入检查按钮，防止重复点击
    EnableWindow(g_hSaveBtn, FALSE);
    
    int totalPackets = 0;
    int httpPackets = 0;
    int suspiciousPackets = 0;
    std::vector<std::string> suspiciousRequests;
    
    // 清空攻击日志
    SetWindowTextW(g_hAttackLog, L"正在检查SQL注入攻击，请稍候...");
    
    // 显示进度信息
    LogAttackW(L"开始SQL注入分析...");
    
    // 遍历所有捕获的数据包
    {
        std::lock_guard<std::mutex> lock(g_packetsMutex);
        totalPackets = g_packets.size();
        
        int processedPackets = 0;
        int lastProgressPercent = 0;
        
        for (const auto& packet : g_packets) {
            // 显示进度
            processedPackets++;
            int progressPercent = (processedPackets * 100) / totalPackets;
            if (progressPercent > lastProgressPercent && progressPercent % 10 == 0) {
                wchar_t progress[64];
                swprintf(progress, L"分析进度: %d%%", progressPercent);
                LogAttackW(progress);
                lastProgressPercent = progressPercent;
                
                // 处理Windows消息队列，保持UI响应
                MSG msg;
                while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
            }
            
            // 跳过太小的数据包
            if (packet.size() < sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER)) {
                continue;
            }
            
            // 解析以太网帧头
            ETHERNET_HEADER* eth_header = (ETHERNET_HEADER*)packet.data();
            
            // 检查是否是IP数据包
            if (ntohs(eth_header->type) != 0x0800) {
                continue;
            }
            
            // 解析IP头
            IP_HEADER* ip_header = (IP_HEADER*)(packet.data() + sizeof(ETHERNET_HEADER));
            int ip_header_len = (ip_header->ver_ihl & 0x0F) * 4;
            
            // 检查是否是TCP数据包
            if (ip_header->protocol != 6) {
                continue;
            }
            
            // 解析TCP头
            TCP_HEADER* tcp_header = (TCP_HEADER*)(packet.data() + sizeof(ETHERNET_HEADER) + ip_header_len);
            int tcp_header_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
            
            // 检查是否是HTTP请求（目标端口80或443）
            if (ntohs(tcp_header->dst_port) != 80 && ntohs(tcp_header->dst_port) != 443) {
                continue;
            }
            
            httpPackets++;
            
            // 提取HTTP负载
            int payload_offset = sizeof(ETHERNET_HEADER) + ip_header_len + tcp_header_len;
            int payload_len = packet.size() - payload_offset;
            
            if (payload_len <= 0) {
                continue;
            }
            
            // 将负载转换为字符串进行分析
            std::string payload(reinterpret_cast<const char*>(packet.data() + payload_offset), payload_len);
            
            // 检查是否包含SQL注入模式
            if (DetectSQLInjection(payload)) {
                suspiciousPackets++;
                
                // 提取IP和端口信息
                char src_ip[16] = {0};
                sprintf(src_ip, "%d.%d.%d.%d", 
                        (ip_header->src_addr) & 0xFF,
                        (ip_header->src_addr >> 8) & 0xFF,
                        (ip_header->src_addr >> 16) & 0xFF,
                        (ip_header->src_addr >> 24) & 0xFF);
                
                // 使用宽字符版本的日志函数
                wchar_t wsrc_ip[16] = {0};
                MultiByteToWideChar(CP_ACP, 0, src_ip, -1, wsrc_ip, 16);
                
                wchar_t wlog_message[512];
                swprintf(wlog_message, L"检测到疑似SQL注入攻击: %s:%d -> %d [%zu bytes]", 
                        wsrc_ip, ntohs(tcp_header->src_port), 
                        ntohs(tcp_header->dst_port), payload.length());
                
                LogAttackW(wlog_message);
                
                // 保存请求的前100个字符以供参考，替换不可打印字符
                std::string safePayload = SafePayloadToString(payload.substr(0, 100));
                if (payload.length() > 100) {
                    safePayload += "...";
                }
                suspiciousRequests.push_back(safePayload);
            }
        }
    }
    
    LogAttack("SQL注入分析完成");
    
    // 显示结果
    wchar_t result[1024];
    swprintf(result, L"SQL注入检查完成:\n共分析 %d 个数据包\n其中 %d 个HTTP包\n检测到 %d 个疑似SQL注入攻击", 
             totalPackets, httpPackets, suspiciousPackets);
    
    MessageBoxW(g_hWnd, result, L"SQL注入检查结果", MB_ICONINFORMATION);
    
    // 如果找到可疑请求，添加到日志
    if (!suspiciousRequests.empty()) {
        LogAttack("------ 可疑SQL注入请求摘要 ------");
        for (size_t i = 0; i < suspiciousRequests.size(); i++) {
            // 安全地添加索引和请求内容
            std::string index_str = "[" + std::to_string(i + 1) + "] ";
            LogAttack((index_str + suspiciousRequests[i]).c_str());
        }
        LogAttack("------ 检查结束 ------");
    } else if (httpPackets > 0) {
        LogAttack("未检测到SQL注入攻击");
    } else {
        LogAttack("未检测到HTTP请求");
    }
    
    // 重新启用SQL注入检查按钮
    EnableWindow(g_hSaveBtn, TRUE);
}

void OpenPcapFile() {
    // 如果正在捕获，先停止
    if (g_isCapturing) {
        int result = MessageBoxW(g_hWnd, L"当前正在捕获数据包，是否停止捕获并打开文件？", 
                               L"确认", MB_YESNO | MB_ICONQUESTION);
        if (result == IDYES) {
            StopCapture();
        } else {
            return;
        }
    }
    
    // 清空现有数据包
    {
        std::lock_guard<std::mutex> lock(g_packetsMutex);
        g_packets.clear();
    }
    
    // 清空列表视图
    ListView_DeleteAllItems(g_hPacketList);
    
    // 清空树视图
    TreeView_DeleteAllItems(g_hPacketDetail);
    
    // 创建打开文件对话框
    wchar_t filename[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"PCAP文件 (*.pcap;*.pcapng)\0*.pcap;*.pcapng\0所有文件 (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    
    if (!GetOpenFileNameW(&ofn)) {
        return; // 用户取消
    }
    
    // 转换宽字符文件名为多字节字符串
    char mbFilename[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, filename, -1, mbFilename, MAX_PATH, NULL, NULL);
    
    // 设置状态消息
    SetWindowTextW(g_hAttackLog, L"正在加载文件，请稍候...");
    
    // 使用宽字符版本的日志函数
    LogAttackW(L"开始加载PCAP文件...");
    
    // 打开PCAP文件
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* pcap = pcap_open_offline(mbFilename, errbuf);
    
    if (!pcap) {
        std::string err_msg = "无法打开PCAP文件: " + std::string(errbuf);
        LogAttack(err_msg.c_str());
        MessageBoxW(g_hWnd, L"无法打开PCAP文件，请确认文件格式正确", L"错误", MB_ICONERROR);
        return;
    }
    
    // 读取并处理数据包
    pcap_pkthdr* header;
    const u_char* data;
    int packet_count = 0;
    int ret;
    
    while ((ret = pcap_next_ex(pcap, &header, &data)) == 1) {
        // 处理数据包
        ProcessPacket(data, header);
        packet_count++;
        
        // 每处理100个数据包更新一次UI，保持响应性
        if (packet_count % 100 == 0) {
            wchar_t progress_msg[64];
            swprintf(progress_msg, L"已加载 %d 个数据包...", packet_count);
            LogAttackW(progress_msg);
            
            // 处理Windows消息队列，保持UI响应
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }
    
    // 关闭PCAP文件
    pcap_close(pcap);
    
    // 更新UI
    wchar_t complete_msg[64];
    swprintf(complete_msg, L"成功加载 %d 个数据包", packet_count);
    LogAttackW(complete_msg);
    
    // 更新窗口标题显示当前打开的文件
    std::wstring fileName = ofn.lpstrFile;
    size_t lastSlash = fileName.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        fileName = fileName.substr(lastSlash + 1);
    }
    
    std::wstring windowTitle = L"网络流量分析工具 - " + fileName;
    SetWindowTextW(g_hWnd, windowTitle.c_str());
    
    // 使按钮状态正确
    EnableWindow(g_hStartBtn, TRUE);
    EnableWindow(g_hStopBtn, FALSE);
    EnableWindow(g_hSaveBtn, TRUE);  // 启用SQL注入分析按钮
    
    MessageBoxW(g_hWnd, L"文件加载完成！", L"成功", MB_ICONINFORMATION);
}