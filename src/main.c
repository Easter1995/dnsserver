#include <stdio.h>
#include "dns.h"
#include "config.h"
#include "handler.h"
#include "resource.h"
#include "list.h"

int main(int argc, char **argv) {
    
    /* 初始化Windows套接字 */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    /* 初始化DNS服务器配置 */
    DNS_CONFIG config = config_init(argc, argv);
    
    /* 初始化DNS服务器运行时 */
    DNS_RUNTIME runtime = runtime_init(&config);

    /* 初始化请求队列 */
    init_request_queue(&request_queue);
    
    /* 初始化拦截列表 */
    block_table_init();
    
    /* 初始化cache */
    cache_init();
    
    /* 初始化socket */
    socket_init(&runtime);

    /* 创建工作线程 */
    HANDLE worker_threads[THREAD_SIZE];
    for (int i = 0; i < THREAD_SIZE; i++) {
        worker_threads[i] = (HANDLE)_beginthreadex(NULL, 0, worker_thread, (void*)&runtime, 0, NULL);
    }
    
    /* 处理客户端请求 */
    loop(&runtime);

    /* 等待工作线程结束工作 */
    WaitForMultipleObjects(THREAD_SIZE, worker_threads, TRUE, INFINITE);

    /* 销毁请求队列 */
    destroy_request_queue(&request_queue);

    /* 程序退出 */
    WSACleanup();
    return 0;
    
}