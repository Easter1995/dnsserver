/* 处理网络连接相关以及请求处理 */
#ifndef HANDLER_H
#define HANDLER_H
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <process.h>
#include <winsock2.h>
#include "list.h"
#include "dns.h"
#include "thread.h"
#include "config.h"

#pragma comment(lib, "ws2_32.lib")

/* 初始化客户端和服务端的socket */
void socket_init(DNS_RUNTIME *runtime);

/* 工作线程 */
unsigned __stdcall worker_thread(void* arg);

/* 判断此ip是否可以存入cache */
int IsCacheable(DNSQType type);

/* 初始化一个DNS空包 */
DNS_PKT init_DNSpacket();

#endif