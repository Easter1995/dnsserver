/* 线程初始化与线程分配 */
#include "thread.h"

/**
 * 初始化线程池
 */
void init_thread_pool()
{
    thread_pool.num_threads = THREAD_COUNT; // 初始线程为最少线程量
    thread_pool.mutex = CreateMutex(NULL, FALSE, NULL);                 // 创建互斥锁
    thread_pool.cond = CreateEvent(NULL, FALSE, FALSE, NULL);           // 创建条件变量
    thread_pool.shutdown_event = CreateEvent(NULL, FALSE, FALSE, NULL); // 线程池关闭事件
    init_request_queue(&thread_pool.request_queue);

    // 创建初始线程
    for (int i = 0; i < thread_pool.num_threads; i++)
    {
        // 保存线程句柄
        thread_pool.threads[i] = (HANDLE)_beginthreadex(NULL, 0, worker_thread, &runtime, 0, NULL);
    }
}

/**
 * 销毁线程池
 */
void destroy_thread_pool()
{
    // 设置关闭事件
    SetEvent(thread_pool.shutdown_event);

    // 等待所有线程退出
    WaitForMultipleObjects(thread_pool.num_threads, thread_pool.threads, TRUE, INFINITE);

    for (int i = 0; i < thread_pool.num_threads; i++)
    {
        CloseHandle(thread_pool.threads[i]);
    }
    destroy_request_queue(&thread_pool.request_queue);
    CloseHandle(thread_pool.mutex);
    CloseHandle(thread_pool.cond);
    CloseHandle(thread_pool.shutdown_event);
}

/**
 * 有新任务，入队，调整线程数量
 */
void enqueue_task(struct sockaddr_in client_addr, DNS_PKT pkt, Buffer buffer)
{
    enqueue_request(&thread_pool.request_queue, client_addr, pkt, buffer);
}

/**
 * 出队一个任务
 */
Request *dequeue_task(Request *request)
{
    WaitForSingleObject(thread_pool.mutex, INFINITE); // 获取线程池资源
    Request *req = dequeue_request(&thread_pool.request_queue);
    if (req) {
        thread_pool.request_queue.queue_len--;
    }
    ReleaseMutex(thread_pool.mutex); // 释放锁，归还线程池资源
    return req;
}

/**
 * 初始化任务队列
 */
void init_request_queue(RequestQueue *queue)
{
    INIT_LIST_HEAD(&queue->head);                        // 初始化链表头
    queue->queue_len = 0;
    queue->mutex = CreateMutex(NULL, FALSE, NULL);       // 创建互斥锁
    queue->cond = CreateEvent(NULL, FALSE, FALSE, NULL); // 创建条件变量
}

/**
 * 向任务队列添加任务
 */
void enqueue_request(RequestQueue *queue, struct sockaddr_in client_addr, DNS_PKT pkt, Buffer buffer)
{
    Request *request = (Request *)malloc(sizeof(Request)); // 分配新的请求节点
    request->client_addr = client_addr;                    // 设置客户端地址
    request->buffer = buffer;                              // 设置数据缓冲区
    request->dns_packet = pkt;                             // 设置接收到的dns包
    INIT_LIST_HEAD(&request->list);                        // 初始化链表节点

    WaitForSingleObject(queue->mutex, INFINITE); // 获取锁
    list_add_tail(&request->list, &queue->head); // 添加到链表尾部
    SetEvent(thread_pool.cond);                  // 通知线程
    queue->queue_len++;                          // 队列长度++
    ReleaseMutex(queue->mutex);                  // 释放锁
}

/**
 * 从任务队列获取任务
 */
Request* dequeue_request(RequestQueue *queue)
{
    WaitForSingleObject(queue->mutex, INFINITE); // 加锁
    if (list_empty(&queue->head)) { // 如果队列为空，解锁并返回NULL
        ReleaseMutex(queue->mutex);
        return NULL;
    }

    struct list_head *pos = queue->head.next; // 获取队列头部的节点
    list_del(pos);                            // 从队列中删除
    ReleaseMutex(queue->mutex);               // 解锁

    return list_entry(pos, Request, list);    // 返回请求节点
}

/**
 * 销毁任务队列
 */
void destroy_request_queue(RequestQueue *queue)
{
    CloseHandle(queue->mutex); // 关闭互斥锁
    CloseHandle(queue->cond);  // 关闭条件变量
}