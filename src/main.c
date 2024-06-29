#include <stdio.h>
#include "dns.h"
#include "config.h"
#include "handler.h"
#include "resource.h"

#define BUFF_SIZE 1024
#define THREAD_SIZE 8
#define PRINT_SIZE 256

int main(int argc, char **argv) {
    /* 初始化DNS服务器配置 */
    DNS_CONFIG config = config_init(argc, argv);
    /* 初始化DNS服务器运行时 */
    DNS_RUNTIME runtime = runtime_init(&config);
    /* 初始化共享资源 */
    BLOCK_TABLE* block_table = block_table_init();
    /* 初始化socket */
    socket_init(&runtime);
    /* 处理客户端请求 */
    
}