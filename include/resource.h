/* 多线程共享资源管理 */
#ifndef RESOURCE_H
#define RESOURCE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <time.h>
#include "dns.h"
#include "list.h"
#include "trie.h"

#define MAX_TABLE_LEN 1024
#define MAX_CACHE_LEN 1024
#define MAX_IP_COUNT 10

/* 拦截列表，使用字典树存储 */
#define block_table trie

/**
 * 拦截列表
 */
typedef struct BLOCK_TABLE {
  uint32_t ipv4; // IP
  char* name;    // 域名
} BLOCK_TABLE;

/**
 * cache列表
 */
typedef struct CACHE_LIST {
  struct list_head list;
  int list_size;
  HANDLE lock; // 互斥量句柄
} CACHE_LIST;

/**
 * cache条目
 */
typedef struct CACHE_ENTRY {
  struct list_head list; // 包含了这个节点的两个指针
  // 数据部分
  char name[NAME_LEN];
  uint32_t ip;
  time_t expireTime;
  uint32_t count; // LRU算法的计数器
} CACHE_ENTRY;

/* 点分十进制IPv4字符串转换为32位无符号数 */
uint32_t ip_to_u32(char ip[IPv4_LEN]);

/* 初始化拦截表 */
void block_table_init();

/* 初始化cache */
void cache_init();

/* 添加cache */
void cache_add_one(char *name, uint32_t ip, uint32_t ttl);

/* 查找cache */
bool cache_search(char *name, uint32_t *ip_array, int *actual_ip_cnt);

/* 获取cache_list的互斥量句柄 */
HANDLE get_cache_lock();

/* cache列表，使用双向链表存储 */
CACHE_LIST cache_list;

/*缓存数据的关键字*/
typedef struct Key {
    DNSQType qtype; //查询类型
    char name[256]; //待查询字符串
} Key;

/*缓存的数据*/
typedef struct MyData {
    time_t time;          //缓存时间
    uint32_t answerCount; //资源信息的数量
    DNS_RECORD *answers;  //改数据项中的资源信息（例如IP地址、域名等）
} MyData;

#endif