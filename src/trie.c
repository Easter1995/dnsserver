#include "trie.h"
char ALPHABET[37] = "abcdefghijklmnopqrstuvwxyz0123456789.";
/**
 * 初始化字典树
 */
void trie_init() {
    trie = (Trie *)malloc(sizeof(Trie)); // 最开始只有一个根节点
    memset(trie->children, 0, sizeof(trie->children));
    trie->leaf = NULL;
    trie->is_end = false;
}

/**
 * 字典树插入节点
 */
void trie_insert(char *domain, uint32_t ip) {
    Trie *t = trie;
    for (int i = 0; i < strlen(domain); i++) {
        int index = get_char_index(domain[i]);
        if (t->children[index] == NULL) {
            t->children[index] = (Trie *)malloc(sizeof(Trie));
            memset(t->children[index], 0, sizeof(Trie));
            t->children[index]->leaf = NULL;
            t->children[index]->is_end = false;
        }
        t = t->children[index];
    }
    // 最后一个字符的节点标记为域名结尾
    t->is_end = true;
    if (t->leaf == NULL) {
        t->leaf = (Trie_Leaf*)malloc(sizeof(Trie_Leaf));
    }
    t->leaf->ip = ip;
}

/**
 * 获取字符在ALPHABET的索引
 */
int get_char_index(char c) {
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    else if (c >= '0' && c <= '9')
        return c - '0' + 26;
    else if (c == '.')
        return 36;
    return -1; // 错误情况，应该处理错误输入
}

/**
 * 根据域名查找字典树节点
 */
bool trie_search(char *domain, uint32_t *ip) {
    Trie *t = trie;
    for (int i = 0; i < strlen(domain); i++) {
        int index = get_char_index(domain[i]);
        if (t == NULL || t->children[index] == NULL)
            return false; // 没找到
        t = t->children[index];
    }
    // 到达域名末尾，需要检查是否是完整的域名
    if (t->is_end && t->leaf != NULL) {
        *ip = t->leaf->ip;
        return true;
    }
    return false;
}

/**
 * 释放字典树的空间
 */
void trie_free(Trie *t) {
    if (t == NULL)
        return;
    for (int i = 0; i < 38; i++) {
        if (t->children[i] != NULL) {
            trie_free(t->children[i]);
        }
    }
    if (t->leaf != NULL) {
        free(t->leaf);
    }
    free(t);
}