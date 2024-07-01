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
#define DNS_PACKET_SIZE 4096
#define DNS_RECORD_TTL 3600

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
    uint16_t ID;        //会话标识
    uint8_t RD : 1;     //表示期望递归
    uint8_t TC : 1;     //表示可截断的
    uint8_t AA : 1;     //表示授权回答
    uint8_t Opcode : 4; //0表示标准查询，1表示反向查询，2表示服务器状态请求
    uint8_t QR : 1;     //查询、响应标识，0为查询，1为响应
    uint8_t Rcode : 4;  //应答码
    uint8_t Z : 3;      //保留值。在所有请求和应答报文中置为零
    uint8_t RA : 1;     //表示可用递归
    uint16_t QDCOUNT;   //问题数
    uint16_t ANCOUNT;   //回答资源记录数
    uint16_t NSCOUNT;   //授权资源记录数
    uint16_t ARCOUNT;   //附加资源记录数
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
DNS_PKT init_DNSpacket();//初始化DNS空包
Buffer DNSPacket_encode(DNS_PKT packet);//DNS包转buffer
void DNSPacket_decode(Buffer *buffer, DNS_PKT *packet);//buffer转DNS包
void DNSPacket_destroy(DNS_PKT packet);//销毁无用DNS包，解除内存占用
void DNSPacket_print(DNS_PKT *packet);//调试输出一个DNS包的内容
#endif