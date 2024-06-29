#include "trie.h"
char ALPHABET[37] = "abcdefghijklmnopqrstuvwxyz0123456789-";

/**
 * 初始化字典树
 */
void trie_init() {
    trie = (Trie *)malloc(sizeof(Trie)); // 最开始只有一个节点
    memset(trie->children, 0, sizeof(trie->children));
}

/**
 * 字典树插入节点
 */
void trie_insert(char *domain, uint32_t ip, uint32_t ttl) {
    int i;
    Trie *t = trie;
    // 遍历字典树，找到该域名对应的叶子节点，途中如果没有就新建
    for (i = 0; i < strlen(domain); i++) {
        int index = get_char_index(domain[i]);
        if (t->children[index] == NULL) {
            t->children[index] = (Trie *)malloc(sizeof(Trie));
            memset(t->children[index], 0, sizeof(Trie));
        }
        t = t->children[index];
    }
    if (t->children[0] == NULL) {
        t->children[0] = (Trie *)malloc(sizeof(Trie));
        memset(t->children[0], 0, sizeof(Trie));
    }
    // 进入叶子节点，存储数据
    t = t->children[0];
    if (t->leaf == NULL) {
        t->leaf = (Trie_Leaf*)malloc(sizeof(Trie_Leaf));
    }
    t->leaf->ip = ip;
    t->leaf->expireTime = time(NULL) + ttl; // 过期时间是当前时间加上TTL
}

/**
 * 获取字符在ALPHABET的索引
 */
int get_char_index(char c) {
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 1;
    else if (c >= '0' && c <= '9')
        return c - '0' + 27;
    else if (c >= 'A' && c <= 'Z')
        return c - 'A' + 1;
    return 37;
}

/**
 * 根据域名查找字典树节点
 */
bool trie_search(char *domain, uint32_t *ip, uint32_t *ttl) {
    int i;
    Trie *t = trie;
    for (i = 0; i < strlen(domain); i++) {
        int index = get_char_index(domain[i]);
        if (t == NULL)
        return 0; // 没找到
        t = t->children[index];
    }
    t = t->children[0];
    if (t == NULL)
        return 0; // 没找到
    *ip = t->leaf->ip; // 将叶子节点的信息填充进ip
    *ttl = t->leaf->expireTime - time(NULL); // 将剩余生存时间填充进ttl
}

/**
 * 释放字典树的空间
 */
void trie_free() {
    Trie *t = trie;
    if (t == NULL)
        return;
    if (t->children[0])
        free(t->children[0]);
    int i;
    for (i = 1; i < 38; i++) {
        trie_free(t->children[i]);
        free(t);
    }
}