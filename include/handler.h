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

/*主循环*/
void loop(DNS_RUNTIME *runtime);

/*创建一个缓冲区*/
Buffer makeBuffer(int len);

/*标准形式转点分十进制*/
uint32_t *getURL(char *name_ptr, char *res);

/*点分十进制转标准形式*/
uint8_t *toQname(char *name, char *data);

uint8_t *_read32(uint8_t *ptr, uint32_t *value);
uint8_t *_write32(uint8_t *ptr, uint32_t value);
#endif