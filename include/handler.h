/* 处理网络连接相关以及数据处理 */
#ifndef HANDLER_H
#define HANDLER_H
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "dns.h"
#include "config.h"

/* 初始化客户端和服务端的socket */
void socket_init(DNS_RUNTIME *runtime);
/* 判断此ip是否可以存入cache */
int IsCacheable(DNSQType type);
/* 初始化一个DNS空包 */
DNS_PKT init_DNSpacket();

#endif