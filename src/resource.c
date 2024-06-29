#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resource.h"
#include "dns.h"

#define MAX_TABLE_LEN 512
uint32_t block_table_number = 0;

/* 初始化拦截列表 */
BLOCK_TABLE* block_table_init() {
    BLOCK_TABLE* block_table = (BLOCK_TABLE*) malloc(sizeof(BLOCK_TABLE) * MAX_TABLE_LEN);
    // 打开拦截列表文件
    FILE *fp = fopen("D:\\ComputerNetworking\\dnsserver\\src\\blocklist.dic", "r");
    if (fp == NULL) {
        perror("fopen error");
        exit(0);
    }
    
    // 将点分十进制地址转换为32位十进制的无符号整数
    // 并且将转换后的文件信息存入结构体数组并返回
    char ip[IPv4_LEN] = {'\0'};
    char name[NAME_LEN] = {'\0'};
    
    while (fscanf(fp, "%s", ip) != EOF && fscanf(fp, "%s", name) != EOF) {
        uint32_t cnt = 0; // 重置计数器
        int temp_ip[4] = {0}; // 存储ip的四个部分
        // 将IPv4地址的字符串转换为十进制整数
        for (int i = 0; ip[i] != '\0'; i++) {
            if (ip[i] == '.') {
                cnt++;
            } else {
                temp_ip[cnt] = 10 * temp_ip[cnt] + (ip[i] - '0');
            }
        }
        // 存入拦截列表
        block_table[block_table_number].name = malloc(strlen(name) + 1);
        block_table[block_table_number].ipv4 = temp_ip[0] * 256 * 256 * 256 + temp_ip[1] * 256 * 256 + temp_ip[2] * 256 + temp_ip[3];
        strcpy(block_table[block_table_number].name, name);
        block_table_number++;
        printf("block a website: %s\n", block_table[block_table_number - 1].name);
    }

    return block_table;
}