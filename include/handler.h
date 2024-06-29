/* 处理网络连接相关以及数据处理 */
#ifndef HANDLER_H
#define HANDLER_H
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <stdio.h>
#include "dns.h"
#include "config.h"

void socket_init(DNS_RUNTIME *runtime);

#endif