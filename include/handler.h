/* 处理网络连接相关以及数据处理 */
#ifndef HANDLER_H
#define HANDLER_H
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "dns.h"
#include "config.h"

#define THREAD_SIZE 8

/**
 * 定义任务结构
 */
typedef struct Task {
    struct sockaddr_in client_addr; // 客户端地址+端口号
    struct Buffer buffer; // 数据缓存区
    struct list_head list; // 连接多个task
} Task;

/**
 * 定义任务队列
 */
typedef struct TaskQueue {
    struct list_head head;
    CRITICAL_SECTION mutex;
    CONDITION_VARIABLE cond;
    int size;
} TaskQueue;
/* 线程池 */
HANDLE thread_pool[THREAD_SIZE];
/* 任务队列 */
TaskQueue taskQueue;
/* 任务队列非空事件 */
HANDLE taskQueueNotEmptyEvent; 

/* 初始化客户端和服务端的socket */
void socket_init(DNS_RUNTIME *runtime);
/* 判断此ip是否可以存入cache */
int IsCacheable(DNSQType type);
/* 初始化一个DNS空包 */
DNS_PKT init_DNSpacket();

#endif