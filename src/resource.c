#include "resource.h"

uint32_t block_table_number = 0;

/**
 * 初始化拦截列表
 */
void block_table_init() {
    trie_init();
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
        // 将IPv4地址的字符串转换为十进制整数
        uint32_t ipv4 = ip_to_u32(ip);
        // 存入拦截列表
        trie_insert(name, ipv4);
    }
}
/**
 * 初始化cache_list里面的链表部分，链表长度设为0
 */
void cache_init() {
    memset(&cache_list.list, 0, sizeof(cache_list.list));
    INIT_LIST_HEAD(&cache_list.list);
    cache_list.list_size = 0;
    cache_list.lock = CreateMutex(NULL, FALSE, NULL); // 创建互斥量

    if (cache_list.lock == NULL) {
        perror("Error creating mutex for cache_list.");
        exit(EXIT_FAILURE);
    }
}

/**
 * 添加一条cache
 */
void cache_add_one(char *name, uint32_t ip, uint32_t ttl) {
    CACHE_ENTRY* cache_entry = (CACHE_ENTRY *)malloc(sizeof(CACHE_ENTRY));
    strcpy(cache_entry->name, name);
    cache_entry->ip = ip;
    cache_entry->count = 0;
    cache_entry->expireTime = time(NULL) + ttl;

    // 等待获取互斥量的控制权
    DWORD dwWaitResult = WaitForSingleObject(cache_list.lock, INFINITE);

    switch (dwWaitResult) {
        case WAIT_OBJECT_0:
            // 成功获取互斥量，可以访问共享资源
            // 链表满了，优先删除expire time到了的节点，然后考虑使用LRU删除一个节点
            if (cache_list.list_size == MAX_CACHE_LEN) {
                struct list_head *pos, *n;
                CACHE_ENTRY *entry; // 当前遍历到的节点
                CACHE_ENTRY *entry_to_del = NULL; // 要删除的节点
                bool has_find_expired_one = false;
                uint32_t max_lru_cnt = 0;

                list_for_each_safe(pos, n, &cache_list.list) {
                    entry = list_entry(pos, CACHE_ENTRY, list);
                    // 删除所有超时的链表
                    if (entry->expireTime < time(NULL)) {
                        has_find_expired_one = true;
                        list_del(&entry->list);
                        free(entry);
                        cache_list.list_size--;
                    }
                    // 找出LRU最大的链表，如果已经删除了超时的就不用删除这一条了
                    if (entry->count > max_lru_cnt && !has_find_expired_one) {
                        max_lru_cnt = entry->count;
                        entry_to_del = entry;
                    }
                }

                // 如果没有超时的，就删除计数器最大的
                if (!has_find_expired_one && entry_to_del) {
                    list_del(&entry_to_del->list);
                    free(entry_to_del);
                    cache_list.list_size--;
                }
            }

            // LRU：除新加入的节点外，其余未命中节点计数器+1
            struct list_head *pos;
            CACHE_ENTRY *entry; // 当前遍历到的节点
            list_for_each(pos, &cache_list.list) {
                entry = list_entry(pos, CACHE_ENTRY, list);
                entry->count++;
            }

            // 添加新节点到链表头部
            list_add(&cache_entry->list, &cache_list.list);
            cache_list.list_size++;
            ReleaseMutex(cache_list.lock); // 释放互斥量
            break;
        case WAIT_ABANDONED:
            // 互斥量已被放弃
            free(cache_entry);
            break;
        default:
            // 获取互斥量失败
            perror("Error waiting for mutex.");
            free(cache_entry);
            break;
    }
}

/**
 * 查找一条cache并返回ip，若找到，其余未命中cache的count++
 */
bool cache_search(char *name, uint32_t* ip) {
    bool ret = false;
    uint32_t hit_cnt = 0; // 命中节点的计数器值
    struct list_head *pos;
    CACHE_ENTRY *entry; // 当前遍历到的节点
    CACHE_ENTRY *hit_entry = NULL; // 命中的节点

    // 等待获取互斥量的控制权
    DWORD dwWaitResult = WaitForSingleObject(cache_list.lock, INFINITE);

    switch (dwWaitResult) {
        case WAIT_OBJECT_0:
            // 成功获取互斥量，可以访问共享资源
            list_for_each(pos, &cache_list.list) {
                // cache命中
                if (strcmp(entry->name, name) == 0) {
                    // 命中了一个超时的cache，将其删除
                    if (entry->expireTime < time(NULL)) {
                        list_del(&entry->list);
                        return false;
                    }
                    ret = true;
                    hit_entry = entry;
                    hit_cnt = entry->count;
                    *ip = entry->ip;
                    entry->count = 0;
                }
            }
            if (ret == true) {
                list_for_each(pos, &cache_list.list) {
                    // 未命中节点计数器+1
                    if (entry->count > hit_entry->count) {
                        entry->count++;
                    }
                }
            }
            ReleaseMutex(cache_list.lock); // 释放互斥量
            break;
        case WAIT_ABANDONED:
            // 互斥量已被放弃
            ret = false;
            break;
        default:
            // 获取互斥量失败
            perror("Error waiting for mutex.");
            ret = false;
            break;
    }
    return ret;
}

/**
 * 点分十进制->u32
 */
uint32_t ip_to_u32(char ip[IPv4_LEN]) {
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
    uint32_t ipv4 = temp_ip[0] * 256 * 256 * 256 + temp_ip[1] * 256 * 256 + temp_ip[2] * 256 + temp_ip[3];
    return ipv4;
}