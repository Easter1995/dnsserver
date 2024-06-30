/* 处理网络连接相关以及请求处理 */
#ifndef HANDLER_H
#define HANDLER_H
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <process.h>
#include "list.h"
#include "dns.h"
#include "thread.h"
#include "config.h"
#include "resource.h"

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

/*处理上游应答*/
void HandleFromUpstream(DNS_RUNTIME *runtime);

/*创建一个缓冲区*/
Buffer makeBuffer(int len);

/*标准形式转点分十进制*/
uint32_t *getURL(char *name_ptr, char *res);

/*点分十进制转标准形式*/
uint8_t *toQname(char *name, char *data);

/*读取数据时指针的移动*/
uint8_t *_read32(uint8_t *ptr, uint32_t *value);
uint8_t *_write32(uint8_t *ptr, uint32_t value);
uint8_t *_read16(uint8_t *ptr, uint16_t *value);
uint8_t *_write16(uint8_t *ptr, uint16_t value);
uint8_t *_read8(uint8_t *ptr, uint8_t *value);
uint8_t *_write8(uint8_t *ptr, uint8_t value);

/*寻找空闲回话id*/
uint16_t setIdMap(IdMap *idMap, IdMap item, uint16_t curMaxId);

IdMap getIdMap(IdMap *idMap, uint16_t i);

/*接受DNS包*/
DNS_PKT recvPacket(DNS_RUNTIME *runtime, SOCKET socket, Buffer *buffer, struct sockaddr_in *client_Addr, int *error);

/*生成回应包*/
DNS_PKT prepare_answerPacket(uint32_t *ip, DNS_PKT packet, int ip_count);

#endif