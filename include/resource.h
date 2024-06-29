/* 多线程共享资源管理 */
#ifndef RESOURCE_H
#define RESOURCE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"
#include "list.h"
#include "trie.h"

#define MAX_TABLE_LEN 512
#define MAX_CACHE_LEN 256

/**
 * 拦截列表
 */
typedef struct BLOCK_TABLE {
  uint32_t ipv4; // IP
  char* name;    // 域名
} BLOCK_TABLE;

typedef struct CACHE_LIST {
  struct list_head list;
  int list_size;
} CACHE_LIST;

/* 初始化拦截表 */
void block_table_init();
/* 初始化cache */
void cache_init();

BLOCK_TABLE* block_table;
CACHE_LIST cache_list;

#endif