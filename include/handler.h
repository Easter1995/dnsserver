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
#include <assert.h>
#include "list.h"
#include "dns.h"
#include "thread.h"
#include "config.h"
#include "resource.h"

#pragma comment(lib, "ws2_32.lib")
#define DNS_COMPRESSION_POINTER(offset) (0xC000 | (offset))

/* 初始化客户端和服务端的socket */
void socket_init(DNS_RUNTIME *runtime, DNS_CONFIG *config);

/* 工作线程 */
unsigned __stdcall worker_thread(void* arg);

/* 初始化一个DNS空包 */
DNS_PKT init_DNSpacket();

/* 主循环 */
void loop(DNS_RUNTIME *runtime);

/* 处理上游应答 */
void HandleFromUpstream(DNS_RUNTIME *runtime);

/* 创建一个缓冲区 */
Buffer makeBuffer(int len);

/* 数字形式转换成点分形式 */
int toDot(char *ptr, char *start, char *newStr);

/* 点分形式转换成数字形式 */
uint8_t toQname(char *name, char *data);

/* 读取数据时指针的移动 */
uint8_t *_read32(uint8_t *ptr, uint32_t *value);
uint8_t _write32(uint8_t *ptr, uint32_t value);
uint8_t *_read16(uint8_t *ptr, uint16_t *value);
uint8_t _write16(uint8_t *ptr, uint16_t value);
uint8_t *_read8(uint8_t *ptr, uint8_t *value);
uint8_t _write8(uint8_t *ptr, uint8_t value);

/* 寻找空闲会话id */
uint16_t setIdMap(IdMap *idMap, IdMap item, uint16_t curMaxId);

/* 释放会话id并返回会话id对应的IdMap信息 */
IdMap getIdMap(IdMap *idMap, uint16_t i);

/* 接受DNS包 */
DNS_PKT recvPacket(DNS_RUNTIME *runtime, SOCKET socket, Buffer *buffer, struct sockaddr_in *client_Addr, int *error);

/* 生成回应包 */
void prepare_answerPacket(uint32_t *ip, DNS_PKT *packet, int ip_count);

#endif