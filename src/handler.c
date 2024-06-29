#include "handler.h"

/**
 * 初始化socket
 */
void socket_init(DNS_RUNTIME *runtime) {
    WSADATA wsa_data;
    // 使用winsock2.2版本
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
    uint16_t default_port = 53;
    // 监听请求的socket
    runtime->server = socket(AF_INET, SOCK_DGRAM, 0);
    runtime->listen_addr.sin_family = AF_INET; // 使用IPv4
    runtime->listen_addr.sin_addr.s_addr = INADDR_ANY; // 监听所有本地网络接口的传入数据
    runtime->listen_addr.sin_port = htons(default_port); // 默认使用53号端口
    int ret = bind(runtime->server, (struct sockaddr*)&runtime->listen_addr, sizeof(runtime->listen_addr));
    if (ret < 0) {
        printf("ERROR: bind faild: %d\n", errno);
        exit(-1);
    }
    // 发出请求的socket
    runtime->client = socket(AF_INET, SOCK_DGRAM, 0);
    runtime->listen_addr.sin_family = AF_INET; // 使用IPv4
    runtime->listen_addr.sin_port = htons(default_port); // 默认使用53号端口
    // 将点分十进制形式的 IP 地址转换为网络字节序的二进制形式
    if (inet_pton(AF_INET, runtime->config.upstream_server_IP, &runtime->upstream_addr.sin_addr) <= 0) {
        printf("ERROR: inet_pton failed\n");
        exit(-1);
    }
}

/**
 * 循环处理用户请求
 */
void loop(DNS_RUNTIME *runtime) {
    
}