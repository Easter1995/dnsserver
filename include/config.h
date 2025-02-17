/* 配置和管理 DNS 中继服务器的运行时信息和服务器配置 */
/* 程序的初始化动作 */
#ifndef CONFIG_H
#define CONFIG_H
#define IDMAP_TIMEOUT 5
#include "list.h"
#include "resource.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#pragma comment(lib, "Ws2_32.lib")

/* DNS服务器的配置 */
typedef struct DNS_CONFIG
{
    boolean debug;               // 是否输出debug信息
    boolean debug_2;             // 二级调试信息
    int port;                    // 监听端口号
    char upstream_server_IP[16]; // 上游DNS服务器的IP
} DNS_CONFIG;

/* 程序运行时 */
typedef struct DNS_RUNTIME
{
    DNS_CONFIG config;                // 服务器配置
    boolean quit;                     // 程序是否退出
    SOCKET server;                    // 与客户端通信的socket
    SOCKET client;                    // 与上游服务器通信的socket
    IdMap *idmap;                     // IdMap数组，用于会话id管理
    uint16_t maxId;                   // 上一次向上游服务器发送查询请求时所使用的ID号
    struct sockaddr_in listen_addr;   // 监听地址
    struct sockaddr_in upstream_addr; // 上级DNS服务器地址
} DNS_RUNTIME;

/* 初始化配置 */
DNS_CONFIG config_init(int argc, char *argv[]);

/* 初始化运行时 */
DNS_RUNTIME runtime_init(DNS_CONFIG *config);

/* 销毁运行时 */
void destroyRuntime(DNS_RUNTIME *runtime);

/* 运行时 */
DNS_RUNTIME runtime;

/* 配置 */
DNS_CONFIG config;

#endif