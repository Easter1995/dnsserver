#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resource.h"
#include "dns.h"
#define MAX_TABLE_LEN 1024
/* 拦截列表 */
BLOCK_TABLE* block_table;
uint32_t cnt = 0;

BLOCK_TABLE* block_table_init() {
    block_table = (BLOCK_TABLE*) malloc(sizeof(BLOCK_TABLE) * MAX_TABLE_LEN);
    // 打开拦截列表文件
    FILE *fp = fopen("./blocklist.txt", "r");
    if (fp == NULL) {
        printf("no such file!");
        return NULL;
    }
    // 将文件信息存入结构体数组并返回
    char ip[32] = {'\0'};
    char name[NAME_LEN] = {'\0'};
    while (fscanf(fp, "%s", ip) != EOF) {
        fscanf(fp, "%s", name);
        strcpy(block_table[cnt].ipv4, ip);
        strcpy(block_table[cnt].name, name);
    }
    return block_table;
}