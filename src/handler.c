#include "handler.h"
#include "config.h"
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <stdio.h>

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
void loadCache(uint8_t * buff, char * domainName, int qname_length){
    uint8_t * tmp = (buff + LEN_DNS_HEADER + qname_length + LEN_DNS_QUESTION);
    uint32_t * ipv4;
    struct DNS_HEADER * header = (struct DNS_HEADER *) buff;
    uint16_t ANCOUNT = header -> ANCOUNT;
    int cnt = 0;
    while(1) {//跳过TYPE为CNAME的ANSWER，取得第一个TYPE为A的ANSWER的RDATA字段
        uint8_t * name = tmp;
        int name_length = 0;
        while(1) {
            name_length ++;
            if(*name == 0) break;
            if(*name == 0xc0) {
                name_length ++;
                break;
            }
      name ++;
    }

    uint16_t * TYPE = (uint16_t * )(tmp + name_length);
    uint16_t * rd_length = (uint16_t *)(tmp + name_length + 8);
    if(ntohs(*TYPE) == 1) {//回答为A
      ipv4 = (uint32_t *)(tmp + name_length + 10);
      trie_insert(domainName, ntohl(*ipv4));
    }
    tmp = (tmp + name_length + 10 + ntohs(*rd_length));
    cnt ++;
    if(cnt == ANCOUNT) break;
  }

}