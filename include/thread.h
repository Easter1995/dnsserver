/* 线程管理模块 */
#ifndef THREAD_H
#define THREAD_H
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <process.h>
#include "list.h"
#include "dns.h"
#include "handler.h"

// #define THREAD_COUNT_LOW  2    // 低任务量
// #define THREAD_COUNT_MEDIUM  4 // 中等任务量
// #define THREAD_COUNT_HIGH  8   // 高任务量
#define THREAD_COUNT_LOW  1    // 低任务量
#define THREAD_COUNT_MEDIUM  1 // 中等任务量
#define THREAD_COUNT_HIGH  1   // 高任务量

/**
 * 定义任务结构
 */
typedef struct Request{
    struct list_head list;          // 链表节点
    struct sockaddr_in client_addr; // 客户端地址信息
    DNS_PKT dns_packet;             // 收到的包
    Buffer buffer;                  // 数据缓冲区
} Request;

/**
 * 定义任务链表
 */
typedef struct {
    struct list_head head; // 链表头
    int queue_len;    // 任务队列长度
    HANDLE mutex;          // 互斥锁
    HANDLE cond;           // 条件变量
} RequestQueue;

/**
 * 定义线程池
 */
typedef struct ThreadPool{
    HANDLE threads[THREAD_COUNT_HIGH]; // 存放线程的句柄
    int num_threads;
    int max_threads;
    RequestQueue request_queue;
    HANDLE mutex;
    HANDLE cond;
    HANDLE shutdown_event;
} ThreadPool;

/* 线程池变量 */
ThreadPool thread_pool;

/* 初始化线程池 */
void init_thread_pool();

/* 销毁线程池 */
void destroy_thread_pool();

/* 调整线程数量 */
void adjust_thread_pool();

/* 初始化任务队列 */
void init_request_queue(RequestQueue* queue);

/* 往请求队列添加请求 */
void enqueue_request(RequestQueue* queue, struct sockaddr_in client_addr, DNS_PKT pkt, Buffer buffer);

/* 往任务队列添加任务 */
void enqueue_task(struct sockaddr_in client_addr, DNS_PKT pkt, Buffer buffer);

/* 从请求队列取出请求 */
Request* dequeue_request(RequestQueue* queue);

/* 从任务队列取出任务 */
Request *dequeue_task(Request *request);

/* 销毁任务队列 */
void destroy_request_queue(RequestQueue* queue);

#endif