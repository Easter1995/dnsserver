/* 配置和管理 DNS 中继服务器的运行时信息和服务器配置 */
#ifndef CONFIG_H
#define CONFIG_H
#define CACHE_SIZE 1024
#include <WinSock2.h>
#include "resource.h"

/* DNS服务器的配置 */
typedef struct DNS_CONFIG {
    boolean debug;               // 是否输出debug信息
    boolean block_list;          // 是否有拦截网站
    char upstream_server_IP[16]; // 上游DNS服务器的IP
} DNS_CONFIG;
/* 程序运行时 */
typedef struct DNS_RUNTIME {
    DNS_CONFIG config;        // 服务器配置
    boolean quit;             // 程序是否退出
} DNS_RUNTIME;

/* 初始化配置 */
DNS_CONFIG config_init(int argc, char *argv[]);
/* 初始化运行时 */
DNS_RUNTIME runtime_init(DNS_CONFIG *config);
#endif