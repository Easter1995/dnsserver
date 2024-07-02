#include "resource.h"

uint32_t block_table_number = 0;

/**
 * 初始化域名-ip对照表
 */
void relay_table_init()
{
    trie_init();
    // 打开域名-ip对照表文件
    FILE *fp = fopen("D:\\ComputerNetworking\\dnsserver\\src\\relaylist.dic", "r");
    if (fp == NULL)
    {
        perror("fopen error");
        exit(0);
    }

    // 将点分十进制地址转换为32位十进制的无符号整数
    // 并且将转换后的文件信息存入结构体数组并返回
    char ip[IPv4_LEN] = {'\0'};
    char name[NAME_LEN] = {'\0'};

    while (fscanf(fp, "%s", ip) != EOF && fscanf(fp, "%s", name) != EOF)
    {
        // 将IPv4地址的字符串转换为十进制整数
        uint32_t ipv4 = ip_to_u32(ip);
        // 存入拦截列表
        trie_insert(name, ipv4);
    }
    fclose(fp); // 关闭文件
}

/**
 * IDMap的初始化
 */
IdMap *initIdMap(){
    IdMap *idmap = (IdMap *)malloc(sizeof(IdMap) * (MAXID + 1)); // 为0-65535共65536个id的IdMap分配空间
    for(int i=0; i <= MAXID; i++){
        idmap[i].time = 0; // 把每一个id的过期时间初始化为0
    }
    return idmap;
}


uint16_t setIdMap(IdMap *idMap, IdMap item, uint16_t curMaxId)
{
    uint16_t originId = curMaxId; // 暂存上次向上级发出查询请求时的会话id
    time_t t = time(NULL);        // 将t设为当前时间
    while (idMap[curMaxId].time >= t)
    {                            // 从上次的会话id开始，寻找空闲id，若过期时间大于当前时间说明id正在被占用
        curMaxId++;              // 若当前id正在被占用，则id++，查看下一个id是否可用
        curMaxId %= (MAXID + 1); // 防止id号超过65535
        if (curMaxId == originId)
        {              // 如果找了一整圈，回到起始的id，说明所有id都被占用，无可用的id号
            return -1; // id分配失败
        }
    }
    idMap[curMaxId % (MAXID + 1)] = item; // 将runtime中的idMap数组的信息更新
    return curMaxId % (MAXID + 1);        // 将当前空闲id设为本次向上游服务器发出请求的id
}

/**
 * 释放会话id并返回会话id对应的IdMap信息
 */
IdMap getIdMap(IdMap *idMap, uint16_t i)
{
    idMap[i].time = 0; // 归还原来的会话id，把过期时间还原为0
    return idMap[i];   // 返回会话id对应的idMap项
}

/**
 * 初始化cache_list里面的链表部分，链表长度设为0
 */
void cache_init()
{
    memset(&cache_list.list, 0, sizeof(cache_list.list));
    INIT_LIST_HEAD(&cache_list.list);
    cache_list.list_size = 0;
    cache_list.lock = CreateMutex(NULL, FALSE, NULL); // 创建互斥量

    if (cache_list.lock == NULL)
    {
        perror("Error creating mutex for cache_list.");
        exit(EXIT_FAILURE);
    }
}

/**
 * 添加ip_cnt条cache
 */
void cache_add(char *name, uint32_t* ip, uint32_t ttl, int ip_cnt)
{
    CACHE_ENTRY *cache_entry = (CACHE_ENTRY *)malloc(sizeof(CACHE_ENTRY));
    
    // 将ip加入ip数组
    for (int i = 0; i < ip_cnt; i++) {
        cache_entry->ip_list[i] = ip[i];
    }
    // 存储域名
    strcpy(cache_entry->name, name);
    
    cache_entry->ip_count = ip_cnt;
    cache_entry->count = 0;
    cache_entry->expireTime = time(NULL) + ttl;

    // 操作cache_list，需要获取互斥锁
    
    // 等待获取互斥量的控制权
    DWORD dwWaitResult = WaitForSingleObject(cache_list.lock, INFINITE);

    switch (dwWaitResult)
    {
    case WAIT_OBJECT_0:
        // 成功获取互斥量，可以访问共享资源
        // 链表满了，优先删除expire time到了的节点，然后考虑使用LRU删除一个节点
        if (cache_list.list_size == MAX_CACHE_LEN)
        {
            struct list_head *pos, *n;
            CACHE_ENTRY *entry;               // 当前遍历到的节点
            CACHE_ENTRY *entry_to_del = NULL; // 要删除的节点
            bool has_find_expired_one = false;
            uint32_t max_lru_cnt = 0;

            list_for_each_safe(pos, n, &cache_list.list)
            {
                entry = list_entry(pos, CACHE_ENTRY, list);
                // 删除所有超时的链表
                if (entry->expireTime < time(NULL))
                {
                    has_find_expired_one = true;
                    list_del(&entry->list);
                    free(entry);
                    cache_list.list_size--;
                }
                // 找出LRU最大的链表，如果已经删除了超时的就不用删除这一条了
                if (entry->count > max_lru_cnt && !has_find_expired_one)
                {
                    max_lru_cnt = entry->count;
                    entry_to_del = entry;
                }
            }

            // 如果没有超时的，就删除计数器最大的
            if (!has_find_expired_one && entry_to_del)
            {
                list_del(&entry_to_del->list);
                free(entry_to_del);
                cache_list.list_size--;
            }
        }

        // LRU：除新加入的节点外，其余未命中节点计数器+1
        struct list_head *pos;
        CACHE_ENTRY *entry; // 当前遍历到的节点
        list_for_each(pos, &cache_list.list)
        {
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
 * 查找一条cache并返回ip数组，若找到，其余未命中cache的count++
 */
bool cache_search(char *name, uint32_t **ip_list, int *actual_ip_cnt)
{
    bool ret = false;
    uint32_t hit_cnt = 0;  // 命中节点的计数器值
    struct list_head *pos; // 当前遍历到的链表节点
    CACHE_ENTRY *entry;    // 当前遍历到的节点
    int i = 0;

    // 等待获取互斥量的控制权
    DWORD dwWaitResult = WaitForSingleObject(cache_list.lock, INFINITE);

    switch (dwWaitResult)
    {
    case WAIT_OBJECT_0:
        // 成功获取互斥量，可以访问共享资源
        list_for_each(pos, &cache_list.list)
        {
            entry = list_entry(pos, CACHE_ENTRY, list);
            // cache命中
            if (strcmp(entry->name, name) == 0)
            {
                // 命中了一个超时的cache，将其删除
                if (entry->expireTime < time(NULL))
                {
                    list_del(&entry->list);
                    continue;
                }
                ret = true;
                hit_cnt = entry->count;
                *ip_list = entry->ip_list;
                *actual_ip_cnt = entry->ip_count;
                entry->count = 0;
            }
        }
        if (ret == true)
        {
            printf("[CACHE] Hit cache\n");
            list_for_each(pos, &cache_list.list)
            {
                entry = list_entry(pos, CACHE_ENTRY, list);
                // 未命中节点计数器+1
                if (entry->count > hit_cnt)
                {
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
uint32_t ip_to_u32(char ip[IPv4_LEN])
{
    uint32_t cnt = 0;     // 重置计数器
    int temp_ip[4] = {0}; // 存储ip的四个部分
    // 将IPv4地址的字符串转换为十进制整数
    for (int i = 0; ip[i] != '\0'; i++)
    {
        if (ip[i] == '.')
        {
            cnt++;
        }
        else
        {
            temp_ip[cnt] = 10 * temp_ip[cnt] + (ip[i] - '0');
        }
    }
    uint32_t ipv4 = temp_ip[0] * 256 * 256 * 256 + temp_ip[1] * 256 * 256 + temp_ip[2] * 256 + temp_ip[3];
    return ipv4;
}

