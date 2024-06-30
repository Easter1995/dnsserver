#include <stdio.h>
#include "dns.h"
#include "config.h"
#include "handler.h"
#include "resource.h"
#include "list.h"
#include "thread.h"

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

    /* 线程池初始化，初始化请求队列，创建工作线程 */
    init_thread_pool();
    
    /* 初始化拦截列表 */
    block_table_init();
    
    /* 初始化cache */
    cache_init();
    
    /* 初始化socket */
    socket_init(&runtime);
    
    /* 处理客户端请求 */
    loop(&runtime);

    /* 等待工作线程结束工作 */
    WaitForMultipleObjects(thread_pool.num_threads, thread_pool.threads, TRUE, INFINITE);

    /* 销毁线程池，销毁请求队列 */
    destroy_thread_pool();

    /* 程序退出 */
    WSACleanup();
    return 0;

}