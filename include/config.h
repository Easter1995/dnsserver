/* 配置和管理 DNS 中继服务器的运行时信息和服务器配置 */
#ifndef CONFIG_H
#define CONFIG_H
#define CACHE_SIZE 1024
#include "list.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")


/* DNS服务器的配置 */
typedef struct DNS_CONFIG {
    boolean debug;               // 是否输出debug信息
    boolean block_list;          // 是否有拦截网站
    int port;                    //监听端口号
    char upstream_server_IP[16]; // 上游DNS服务器的IP
    char hostfile[256];          //HOST文件的文件名
    char cachefile[256];
} DNS_CONFIG;
/* 程序运行时 */
typedef struct DNS_RUNTIME {
    DNS_CONFIG config;                // 服务器配置
    boolean quit;                     // 程序是否退出
    SOCKET server;                    // 接受请求的socket
    SOCKET client;                    // 与上级连接的socket
    IdMap *idmap;                     //ID转换表 （ID：对一次DNS请求的标识，用于确定请求方）
    uint16_t maxId;                   //上一次请求上级时所使用的ID号
    LRUCache *lruCache;               //缓存来自上级的查询结果，如果请求在缓存内，则直接回复
    struct sockaddr_in listen_addr;   // 监听地址
    struct sockaddr_in upstream_addr; // 上级DNS服务器地址
    int totalCount;
} DNS_RUNTIME;
/* 初始化配置 */
DNS_CONFIG config_init(int argc, char *argv[]);
/* 初始化运行时 */
DNS_RUNTIME runtime_init(DNS_CONFIG *config);

#endif