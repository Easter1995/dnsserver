/* 实现字典树 */
#ifndef TRIE_H
#define TRIE_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * 字典树叶子的数据
 */
typedef struct Trie_Leaf {
  uint32_t ip;
  time_t expireTime;
} Trie_Leaf;

/**
 * 字典树节点
 */
typedef struct Trie {
  union {
    struct Trie* children[38]; // 26个字母、0~9、-符号和一个结束标识
    Trie_Leaf* leaf;
  };
} Trie;
Trie* trie;
/* 初始化字典树 */
void trie_init();
/* 在字典树里插入信息 */
void trie_insert(char *domain, uint32_t ip, uint32_t ttl);
/* 获取字符在字母表里的索引 */
int get_char_index(char c);
/* 根据域名查找字典树叶子节点 */
bool trie_search(char *domain, uint32_t *ip, uint32_t *ttl);
/* 释放字典树的空间 */
void trie_free();

#endif