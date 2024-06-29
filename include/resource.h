/* 多线程共享资源管理 */
#ifndef RESOURCE_H
#define RESOURCE_H
#include <stdio.h>
#include <stdint.h>

typedef struct BLOCK_TABLE {
  uint32_t ipv4; // IP
  char* name;    // 域名
} BLOCK_TABLE;
/* 初始化拦截表 */
BLOCK_TABLE* block_table_init(char* block_list);

#endif