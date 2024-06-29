/* dns包的数据结构 */
#ifndef DNS_H
#define DNS_H

#include<stdio.h>
#include <stdint.h>
#define LEN_DNS_HEADER sizeof(struct DNS_HEADER)
#define LEN_DNS_QUESTION sizeof(struct DNS_QUESTION)
#define LEN_DNS_ANSWER sizeof(struct DNS_ANSWER)
#define NAME_LEN 256
#define IPv4_LEN 16

typedef uint8_t bit;
typedef enum {
    QRQUERY,   //DNSpacket类型是query
    QRRESPONSE //DNSpacket类型是response
} DNSPacketQR;

typedef enum {
    QUERY,  //标准查询
    IQUERY, //反向查询
    STATUS  //服务器状态请求
} DNSPacketOP;

typedef enum {
    OK,        //无错误
    FORMERR,   //报文格式错误
    SERVFAIL,  //域名服务器失败
    NXDOMAIN,  //域名不存在
    NOTIMP,    //查询类型不支持
    REFUSED    //查询请求被拒绝
} DNSPacketRC; //表示响应的差错状态

/* Header Section Format */
typedef struct DNS_HEADER {
    uint16_t ID;    //会话标识
    uint8_t RD : 1; //flags标志
    uint8_t TC : 1;
    uint8_t AA : 1;
    uint8_t Opcode : 4;
    uint8_t QR : 1;
    uint8_t Rcode : 4;
    uint8_t Z : 3;
    uint8_t RA : 1;
    uint16_t QDCOUNT;//问题数
    uint16_t ANCOUNT;//回答资源记录数
    uint16_t NSCOUNT;//授权资源记录数
    uint16_t ARCOUNT;//附加资源记录数
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

/* DNS 报文,后三段格式相同，每段都是由0~n个资源记录(Resource Record)构成 */
typedef struct DNS_PKT {
    DNS_HEADER *header;
    DNS_QUESTION *question;   
    DNS_RECORD *answer;     
    DNS_RECORD *authority;  
    DNS_RECORD *additional; 
} DNS_PKT;

typedef struct Buffer {
    uint8_t *data;   //buffer首地址
    uint32_t length; //buffer长度
} Buffer;
Buffer makeBuffer(int len);//生成长度为len的buffer
Buffer DNSPacket_encode(DNS_PKT packet);//DNS包转buffer
void DNSPacket_destroy(DNS_PKT packet);//销毁无用DNS包，解除内存占用
DNS_PKT DNSPacket_decode(Buffer *buffer);//buffer转DNS包
void DNSPacket_fillQuery(DNS_PKT *packet);//填充发送包的基本属性
void DNSPacket_print(DNS_PKT *packet);//调试输出一个DNS包的内容
#endif