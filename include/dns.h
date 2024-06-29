/* dns包的数据结构 */
#ifndef DNS_H
#define DNS_H

#include<stdio.h>
#include <stdint.h>
#define NAME_LEN 256
/* Header Section Format */
typedef struct DNS_HEADER {
    uint16_t ID;
    uint8_t RD : 1;
    uint8_t TC : 1;
    uint8_t AA : 1;
    uint8_t Opcode : 4;
    uint8_t QR : 1;
    uint8_t Rcode : 4;
    uint8_t Z : 3;
    uint8_t RA : 1;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
} DNS_HEADER;

/* Question Section Format */
typedef struct DNS_QUESTION {
    char name[NAME_LEN];  // 域名
    uint16_t Qtype;  // DNS请求的资源类型
    uint16_t Qclass; // DNS查询的地址类型，如IN
} DNS_QUESTION;

/* Resource Record Format */
typedef struct DNS_RECORD {
    char name[NAME_LEN];    // 域名
    uint16_t type;          // 资源记录的类型
    uint16_t addr_class;    // 资源记录的地址类型
    uint32_t TTL;           // 有效时间
    uint16_t rdlength;      // rdata的长度
    char *rdata;            // 指向资源数据的指针
} DNS_RECORD;

/* DNS的资源记录类型 */
typedef enum {
    A = 0x01,     //IPv4地址
    NS = 0x02,    //DNS服务器
    CNAME = 0x05, //域名别名
    SOA = 0x06,   //作为权威区数据的起始资源类型
    NUL = 0x0A,   //空
    PTR = 0x0C,   //反向查询
    MX = 0x0F,    //邮件交换地址
    TXT = 0x10,   //文本符号
    AAAA = 0x1c,  //IPv6地址
    ANY = 0xFF,   //所有
    OPT = 41      //EDNS
} DNSQType;     

/* DNS报文 */
typedef struct DNS_PKT
{
    DNS_HEADER *header;
    DNS_QUESTION *question;
    DNS_RECORD *record;
} DNS_PKT;

#endif