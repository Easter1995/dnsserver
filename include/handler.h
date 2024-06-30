/* 处理网络连接相关以及数据处理 */
/* 线程相关（考虑拆分出去） */
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
#include "list.h"
#include "dns.h"

#pragma comment(lib, "ws2_32.lib")

#define THREAD_SIZE 8

/**
 * 定义任务结构
 */
typedef struct Request{
    struct list_head list;          // 链表节点
    struct sockaddr_in client_addr; // 客户端地址(IP + port)
    Buffer buffer;                  // 数据缓冲区
} Request;

/**
 * 定义任务链表
 */
typedef struct {
    struct list_head head; // 链表头
    HANDLE mutex;          // 互斥锁
    HANDLE cond;           // 条件变量
} RequestQueue;

/* 线程池 */
HANDLE thread_pool[THREAD_SIZE];

/* 任务队列 */
RequestQueue request_queue;

/* 任务队列非空事件 */
HANDLE taskQueueNotEmptyEvent; 

/* 初始化客户端和服务端的socket */
void socket_init(DNS_RUNTIME *runtime);

/* 初始化任务队列 */
void init_request_queue(RequestQueue* queue);

/* 往任务队列添加任务 */
void enqueue_request(RequestQueue* queue, struct sockaddr_in client_addr, Buffer buffer);

/* 从任务队列取出任务 */
Request* dequeue_request(RequestQueue* queue);

/* 销毁任务队列 */
void destroy_request_queue(RequestQueue* queue);

/* 工作线程 */
unsigned __stdcall worker_thread(void* arg);

/* 判断此ip是否可以存入cache */
int IsCacheable(DNSQType type);

/* 初始化一个DNS空包 */
DNS_PKT init_DNSpacket();

#endif