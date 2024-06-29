/* 多线程共享资源管理 */
#ifndef RESOURCE_H
#define RESOURCE_H
#include <stdio.h>
#include <stdint.h>
#include "dns.h"

typedef struct BLOCK_TABLE {
  uint32_t ipv4; // IP
  char* name;    // 域名
} BLOCK_TABLE;
/* 初始化拦截表 */
BLOCK_TABLE* block_table_init();

typedef struct idMap {
    time_t time;             //过期时间
    uint16_t originalId;     //请求方ID
    struct sockaddr_in addr; //请求方IP+端口
} IdMap;
/*初始化ID转换表*/
IdMap *initIdMap();
IdMap getIdMap(IdMap *idMap, uint16_t i);
int setIdMap(IdMap *idMap, IdMap item, uint16_t curMaxId);

/*LRUCache*/
typedef struct {
    int size;           //当前缓存大小
    int capacity;       //缓存容量
    struct hash *table; //哈希表
    /*双向链表，保存所有资源信息，溢出时采用LRU方法从尾部删除*/
    struct node *head; //头结点，后继指向最近更新的数据
    struct node *tail; //尾结点，前驱指向最久未更新的数据，溢出时优先删除此结点（前提是他不是host中的）
} LRUCache;

/*缓存的数据*/
typedef struct MyData {
    time_t time;          //缓存时间
    uint32_t answerCount; //资源信息的数量
    DNS_RECORD *answers;   //改数据项中的资源信息（例如IP地址、域名等）
} MyData;

#endif