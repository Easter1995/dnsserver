#include "handler.h"
#include "config.h"
#include "resource.h"
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <stdio.h>


/**
 * 初始化socket
 */
void socket_init(DNS_RUNTIME *runtime) {
    WSADATA wsa_data;
    // 使用winsock2.2版本
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("ERROR: WSAStartup failed\n");
        exit(-1);
    }

    uint16_t default_port = 53;

    // 监听请求的socket
    runtime->server = socket(AF_INET, SOCK_DGRAM, 0);
    if (runtime->server == INVALID_SOCKET) {
        printf("ERROR: socket creation failed\n");
        WSACleanup();
        exit(-1);
    }

    const int REUSE = 1;
    if (setsockopt(runtime->server, SOL_SOCKET, SO_REUSEADDR, (const char *)&REUSE, sizeof(REUSE)) < 0) {
        printf("ERROR: setsockopt failed\n");
        closesocket(runtime->server);
        WSACleanup();
        exit(-1);
    }

    // 初始化本机服务器地址
    runtime->listen_addr.sin_family = AF_INET; // 使用IPv4
    runtime->listen_addr.sin_addr.s_addr = INADDR_ANY; // 监听所有本地网络接口的传入数据
    runtime->listen_addr.sin_port = htons(runtime->config.port); // 使用配置中指定的端口

    if (bind(runtime->server, (struct sockaddr*)&runtime->listen_addr, sizeof(runtime->listen_addr)) < 0) {
        printf("ERROR: bind failed: %d\n", WSAGetLastError());
        closesocket(runtime->server);
        WSACleanup();
        exit(-1);
    }

    // 发出请求的socket
    runtime->client = socket(AF_INET, SOCK_DGRAM, 0);
    if (runtime->client == INVALID_SOCKET) {
        printf("ERROR: socket creation failed\n");
        closesocket(runtime->server);
        WSACleanup();
        exit(-1);
    }

    // 初始化上游服务器的地址
    runtime->upstream_addr.sin_family = AF_INET; // 使用IPv4
    runtime->upstream_addr.sin_port = htons(default_port); // 默认使用53号端口

    // 将点分十进制形式的 IP 地址转换为网络字节序的二进制形式
    if (inet_pton(AF_INET, runtime->config.upstream_server_IP, &runtime->upstream_addr.sin_addr) <= 0) {
        printf("ERROR: inet_pton failed\n");
        closesocket(runtime->server);
        closesocket(runtime->client);
        WSACleanup();
        exit(-1);
    }
}
int IsCacheable(DNSQType type){
    if (type == A || type == AAAA || type == CNAME || type == PTR || type == NS || type == TXT) {
        return 1;
    }
    return 0;
}

/**
 * 初始化DNS空包
 */
DNS_PKT init_DNSpacket(){
    DNS_PKT packet;
    packet.answer = NULL;
    packet.question = NULL;
    packet.additional = NULL;
    packet.authority = NULL;
    packet.header->QDCOUNT = 0;
    packet.header->ANCOUNT = 0;
    packet.header->NSCOUNT = 0;
    packet.header->ARCOUNT = 0;
    return packet;     //返回空包
}

/**
 * 生成回应包
 */
DNS_PKT prepare_answerPacket(int ip)
{
    DNS_PKT packet;
    packet.header->Rcode = OK;
    packet.header->QR = QRRESPONSE;
    packet.header->ANCOUNT=1;//找到目标ip的数量
    packet.answer=ip;
    return packet;
}
/**
 * 接收DNS包
 */
DNS_PKT recvPacket(DNS_RUNTIME *runtime, SOCKET socket, Buffer *buffer, struct sockaddr_in *client_Addr, int *error){
    int client_AddrLength=sizeof(*client_Addr);
    int recvBytes=recvfrom(socket, (char *)buffer->data, buffer->length, 0, (struct sockaddr *)client_Addr, &client_AddrLength);
    DNS_PKT packet;
    if(recvBytes==SOCKET_ERROR){//若接收包过程出现异常
        printf("recvfrom failed:%d\n",WSAGetLastError());
        *error=-1;//指示DNS包接收状态为故障
        packet=init_DNSpacket();
    }
    else{//正常接受包
        buffer->length=recvBytes;//更新buffer长度字段
        *error=recvBytes;//给函数调用者的标识
        packet=DNSPacket_decode(buffer);
        if(buffer->length==0){
            *error=-2;//指示接收包为空包
            packet=init_DNSpacket();
        }
    }
    if(runtime->config.debug){//输出debug信息
        if(socket==runtime->server){
            printf("Received packet from client %s:%d\n",inet_ntoa(client_Addr->sin_addr),ntohs(client_Addr->sin_port));
        }else{
            printf("Received packet from upstream\n");
        }
    }
    return packet;
}

/**
 * 处理客户端请求
 */
void HandleFromClient(DNS_RUNTIME *runtime){
    Buffer buffer=makeBuffer(DNS_PACKET_SIZE);
    struct sockaddr_in client_Addr;
    int status=0;//指示DNS包接收状态
    DNS_PKT dnspacket=recvPacket(runtime,runtime->server, &buffer, &client_Addr, &status);
    if(status<=0){//接受失败或者为空包
        return;
    }
    free(buffer.data);//释放缓存
    if (dnspacket.header->QR!= QRQUERY || dnspacket.header->QDCOUNT < 1) {//???????
        DNSPacket_destroy(dnspacket); //销毁packet，解除内存占用
        return;
    }
    if (dnspacket.header->QDCOUNT > 1) {//当dns包中问题数量大于1时，将包丢弃
        if (runtime->config.debug) {
            printf("Too many questions. \n");
        }
        dnspacket.header->QR = QRRESPONSE;
        dnspacket.header->Rcode = FORMERR;
        buffer = DNSPacket_encode(dnspacket);
        DNSPacket_destroy(dnspacket);
        sendto(runtime->server, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&client_Addr, sizeof(client_Addr));
        return;
    }
    //先在本地cache中搜索
    if(IsCacheable(dnspacket.question->Qtype)){
        uint32_t target_ip;
        bool find_result=cache_search(dnspacket.question->name,&target_ip);
        if(find_result){//若在cache中查询到了结果
            if(runtime->config.debug){//打印debug信息
                printf("Cache Hint! Expected ip is %d",target_ip);
            }
            DNS_PKT answer_Packet=prepare_answerpacket(target_ip);
            if(runtime->config.debug){//输出调试信息
                printf("Send packet back to client %s:%d\n",inet_ntoa(client_Addr.sin_addr), ntohs(client_Addr.sin_port));
                DNSPacket_print(&answer_Packet);//???????
                runtime->totalCount++;
                printf("TOTAL COUNT %d\n", runtime->totalCount);
                printf("CACHE SIZE %d\n", cache_list.list_size);
            }
            answer_Packet.header->RA = 1;
            buffer = DNSPacket_encode(answer_Packet);//将DNS包转换为buffer，方便发送
            DNSPacket_destroy(answer_Packet);
            int sendBytes = sendto(runtime->server, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&client_Addr, sizeof(sizeof(client_Addr)));//由服务器发给客户端找到的ip信息
            free(buffer.data);//数据发送完后释放缓存
            if (sendBytes == SOCKET_ERROR) {
                printf("sendto failed: %d\n", WSAGetLastError());
                WSACleanup();
            }else
                printf("Sent %d bytes to server.\n",sendBytes);
            return;
        }
    }
    /*若cache未命中，则需要向上级发送包进一步查询*/
    IdMap mapItem;//声明一个ID转换表
    mapItem.addr = client_Addr;//请求方的地址
    mapItem.originalId = dnspacket.header->ID;//请求方的ID
    mapItem.time = time(NULL) + IDMAP_TIMEOUT;//设置该记录的过期时间
    runtime->maxId = setIdMap(runtime->idmap, mapItem, runtime->maxId);
    dnspacket.header->ID = runtime->maxId;
    // 发走
    if (runtime->config.debug) {
        printf("Send packet to upstream\n");
        DNSPacket_print(&dnspacket);
    }
    buffer = DNSPacket_encode(dnspacket);
    DNSPacket_destroy(dnspacket);
    status = sendto(runtime->client, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&runtime->upstream_addr, sizeof(runtime->upstream_addr));
    free(buffer.data);
    if (status < 0) {
        printf("Error sendto: %d\n", WSAGetLastError());
    }
}
/**
 * 处理上游应答
 */
void HandleFromUpstream(DNS_RUNTIME *runtime){
    
}
/**
 * 循环处理用户请求
 */
void loop(DNS_RUNTIME *runtime) {
    fd_set readfds;
    while(1){
        FD_ZERO(&readfds);// 初始化 readfds，清空文件描述符集合
        FD_SET(runtime->server, &readfds);//添加 server 到 readfds 中
        FD_SET(runtime->client,&readfds);//添加 client 到 readfds 中
        struct timeval tv;
        tv.tv_sec = 5;  // 设置超时时间为 5 秒
        tv.tv_usec = 0;
        int ready=select(0,&readfds,NULL,NULL,&tv);
        if(runtime->quit==1)//程序退出
        return;
        if(ready==-1){
            printf("Error in select\n");
        }else if(ready==0){
            printf("Timeout occurred!\n");
        }else{
            if(FD_ISSET(runtime->server,&readfds)){//接受请求的socket可读，进行处理
                HandleFromClient(runtime);
            }
            if(FD_ISSET(runtime->client,&readfds)){//与上级连接的socket可读,进行处理
                HandleFromUpstream(runtime);
            }
        }
    }
}
/**
 * 初始化长度为len的buffer
 */
Buffer makeBuffer(int len) {
    Buffer buffer;
    buffer.data = (uint8_t *)malloc(len * sizeof(uint8_t));
    buffer.length = len;
    return buffer;
}
/**
 * 实现buffer向DNS包的转换
 */
DNS_PKT DNSPacket_decode(Buffer *buffer) {
    DNS_PKT packet;
    uint8_t *data = buffer->data;
    uint8_t tmp8;
    data = _read16(data, &packet.header->ID);//一次读16位
    if (data > buffer->data + buffer->length) {
        buffer->length = 0;
        return packet;
    }
    /* QR+OP+AA+TC+RD */
    data = _read8(data, &tmp8);//一次读8位
    if (data > buffer->data + buffer->length) {
        buffer->length = 0;
        return packet;
    }
    packet.header->QR = (DNSPacketQR)(tmp8 >> 7 & 0x01);
    packet.header->Opcode= (DNSPacketOP)(tmp8 >> 3 & 0x0F);
    packet.header->AA = tmp8 >> 2 & 0x01;
    packet.header->TC = tmp8 >> 1 & 0x01;
    packet.header->RD = tmp8 >> 0 & 0x01;
    /* RA+padding(3)+RCODE */
    data = _read8(data, &tmp8);
    if (data > buffer->data + buffer->length) {
        buffer->length = 0;
        return packet;
    }
    packet.header->RA = tmp8 >> 7 & 0x01;
    packet.header->Rcode = (DNSPacketRC)(tmp8 & 0xF);
    /* Counts */
    data = _read16(data, &packet.header->QDCOUNT);
    if (data > buffer->data + buffer->length) {
        buffer->length = 0;
        return packet;
    }
    data = _read16(data, &packet.header->ANCOUNT);
    if (data > buffer->data + buffer->length) {
        buffer->length = 0;
        return packet;
    }
    data = _read16(data, &packet.header->NSCOUNT);
    if (data > buffer->data + buffer->length) {
        buffer->length = 0;
        return packet;
    }
    data = _read16(data, &packet.header->ARCOUNT);
    if (data > buffer->data + buffer->length) {
        buffer->length = 0;
        return packet;
    }
}

/**
 * 解析数据包时指针的移动
 */
uint8_t *_read32(uint8_t *ptr, uint32_t *value) {
    *value = ntohl(*(uint32_t *)ptr);
    return ptr + 4;
}
uint8_t *_write32(uint8_t *ptr, uint32_t value) {
    *(uint32_t *)ptr = htonl(value);
    return ptr + 4;
}
uint8_t *_read16(uint8_t *ptr, uint16_t *value) {
    *value = ntohs(*(uint16_t *)ptr);
    return ptr + 2;
}
uint8_t *_write16(uint8_t *ptr, uint16_t value) {
    *(uint16_t *)ptr = htons(value);
    return ptr + 2;
}
uint8_t *_read8(uint8_t *ptr, uint8_t *value) {
    *value = *(uint8_t *)ptr;
    return ptr + 1;
}
uint8_t *_write8(uint8_t *ptr, uint8_t value) {
    *(uint8_t *)ptr = value;
    return ptr + 1;
}

/**
 * IDMap的初始化
 */
int setIdMap(IdMap *idMap, IdMap item, uint16_t curMaxId) {
    uint16_t originId = curMaxId;
    time_t t = time(NULL);
    while (idMap[curMaxId].time >= t) {
        curMaxId++;
        curMaxId %= MAXID;
        if (curMaxId == originId) {
            return -1;
        }
    }
    idMap[curMaxId] = item;
    return curMaxId % MAXID;
}