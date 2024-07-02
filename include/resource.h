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

#define MAX_CACHE_LEN 1024
#define MAX_IP_COUNT 10
#define MAXID 65535

/* 域名-ip对照表，使用字典树存储 */
#define block_table trie

/**
 * 域名-ip对照表
 */
typedef struct RELAY_TABLE {
  uint32_t ipv4; // IP
  char* name;    // 域名
} RELAY_TABLE;

/**
 * 定义id表
 */
typedef struct idMap {
    time_t time;             //过期时间
    uint16_t originalId;     //请求方ID
    struct sockaddr_in addr; //请求方IP+端口
} IdMap;

/**
 * cache里面的ip链表
 */
typedef struct IP_NODE {
  struct list_head list;
  uint32_t ip;
} IP_NODE;

/**
 * cache列表头
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
  uint32_t ip_list[MAX_IP_COUNT]; // 当前域名包含的ip
  time_t expireTime; // 超时时间
  uint32_t count; // LRU算法的计数器
  uint32_t ip_count; // 当前域名包含的ip个数
} CACHE_ENTRY; 

/* 点分十进制IPv4字符串转换为32位无符号数 */
uint32_t ip_to_u32(char ip[IPv4_LEN]);

/* 初始化拦截表 */
void relay_table_init();

/* 初始化cache */
void cache_init();

/* 添加cache */
void cache_add(char *name, uint32_t* ip, uint32_t ttl, int ip_cnt);

/* 查找cache */
bool cache_search(char *name, uint32_t **ip_list, int *actual_ip_cnt);

/* cache列表，使用双向链表存储 */
CACHE_LIST cache_list;

#endif