#include "handler.h"
#include "config.h"
#include "resource.h"
#include "list.h"
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

/**
 * 工作线程函数
 * 任务是从请求队列里面取出一个请求并处理这个请求
 * 解码DNS包
 * 查看cache是否命中，未命中向上游服务器发出请求
 */
unsigned __stdcall worker_thread(void* arg) {
    DNS_RUNTIME* runtime = (DNS_RUNTIME*)arg;  // 获取运行时
    while (1) {
        // 等待任务或者关闭事件
        HANDLE events[] = { thread_pool.cond, thread_pool.shutdown_event };
        DWORD wait_result = WaitForMultipleObjects(2, events, FALSE, INFINITE);

        if (wait_result == WAIT_OBJECT_0 + 1) {
            // 第二个句柄触发，收到关闭事件，退出线程
            return 0;
        }

        Request* request = dequeue_request(&thread_pool.request_queue);  // 获取请求
        if (request) {
            struct sockaddr_in client_addr = request->client_addr;  // 获取客户端地址
            Buffer buffer = request->buffer;  // 获取数据缓冲区

            // 处理请求的逻辑
            int status = 0;
            DNS_PKT dnspacket = DNSPacket_decode(&buffer);  // 解码DNS包
            if (buffer.length <= 0) {
                free(buffer.data);
                free(request);
                continue;
            }

            if (dnspacket.header->QR != QRQUERY || dnspacket.header->QDCOUNT < 1) {
                DNSPacket_destroy(dnspacket);
                free(buffer.data);
                free(request);
                continue;
            }

            if (dnspacket.header->QDCOUNT > 1) {
                if (runtime->config.debug) {
                    printf("Too many questions. \n");
                }
                dnspacket.header->QR = QRRESPONSE;
                dnspacket.header->Rcode = FORMERR;
                buffer = DNSPacket_encode(dnspacket);
                DNSPacket_destroy(dnspacket);
                sendto(runtime->server, (char*)buffer.data, buffer.length, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
                free(buffer.data);
                free(request);
                continue;
            }

            if (IsCacheable(dnspacket.question->Qtype)) {
                uint32_t target_ip;
                bool find_result = cache_search(dnspacket.question->name, &target_ip);
                if (find_result) {
                    if (runtime->config.debug) {
                        printf("Cache Hint! Expected ip is %d", target_ip);
                    }
                    DNS_PKT answer_Packet = prepare_answerPacket(target_ip);
                    if (runtime->config.debug) {
                        printf("Send packet back to client %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                        DNSPacket_print(&answer_Packet);
                        runtime->totalCount++;
                        printf("TOTAL COUNT %d\n", runtime->totalCount);
                        printf("CACHE SIZE %d\n", cache_list.list_size);
                    }
                    answer_Packet.header->RA = 1;
                    buffer = DNSPacket_encode(answer_Packet);
                    DNSPacket_destroy(answer_Packet);
                    int sendBytes = sendto(runtime->server, (char*)buffer.data, buffer.length, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
                    free(buffer.data);
                    free(request);
                    if (sendBytes == SOCKET_ERROR) {
                        printf("sendto failed: %d\n", WSAGetLastError());
                        WSACleanup();
                    } else {
                        printf("Sent %d bytes to server.\n", sendBytes);
                    }
                    continue;
                }
            }

            // 如果cache未命中，则向上级服务器查询
            IdMap mapItem;
            mapItem.addr = client_addr;
            mapItem.originalId = dnspacket.header->ID;
            mapItem.time = time(NULL) + IDMAP_TIMEOUT;
            runtime->maxId = setIdMap(runtime->idmap, mapItem, runtime->maxId);
            dnspacket.header->ID = runtime->maxId;
            runtime->maxId = (runtime->maxId + 1) % UINT16_MAX;
            buffer = DNSPacket_encode(dnspacket);
            DNSPacket_destroy(dnspacket);
            struct sockaddr_in upstreamAddr = runtime->upstream_addr;
            int sendBytes = sendto(runtime->client, (char*)buffer.data, buffer.length, 0, (struct sockaddr*)&upstreamAddr, sizeof(upstreamAddr));
            if (sendBytes == SOCKET_ERROR) {
                printf("sendto failed: %d\n", WSAGetLastError());
                WSACleanup();
            } else {
                printf("Sent %d bytes to upstream server.\n", sendBytes);
            }
            free(buffer.data);
            free(request);
        }
    }
    return 0;
}

/**
 * 主线程函数
 * 任务是监听客户端的请求并接受请求
 * 将请求放入请求队列
 */
void HandleFromClient(DNS_RUNTIME* runtime) {
    Buffer buffer = makeBuffer(DNS_PACKET_SIZE);  // 创建缓冲区
    struct sockaddr_in client_Addr; // 存储客户端的地址信息(IP + port)
    int status = 0; // 存储接收数据包的状态

    // 设置文件描述符集
    // 当服务器套接字接收到客户端的连接请求或数据时，操作系统会将该套接字标记为“可读”，这意味着有数据可以读取
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(runtime->server, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;  // 设置超时时间，单位为秒
    timeout.tv_usec = 0;

    // 监视文件描述符集合中的文件描述符是否发生了 I/O 事件
    int activity = select(runtime->server + 1, &read_fds, NULL, NULL, &timeout);

    // 有事件发生，接受包并且往请求队列添加任务
    if (activity > 0 && FD_ISSET(runtime->server, &read_fds)) {
        DNS_PKT dnspacket = recvPacket(runtime, runtime->server, &buffer, &client_Addr, &status);  // 接收数据包
        if (status <= 0) {
            free(buffer.data);
            return;
        }

        enqueue_request(&thread_pool.request_queue, client_Addr, buffer);  // 将请求放入队列
    } else {
        // 没有活动或者select超时
        free(buffer.data);
    }
}

/**
 * 地址是否可以存入cache
 */
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
 * 销毁DNS包
 */
void DNSPacket_destroy(DNS_PKT packet) {
    for (int i = 0; i < packet.header->ANCOUNT; i++) {
        if (packet.answer[i].rdata != NULL) {
            free(packet.answer[i].rdata);
            packet.answer[i].rdata = NULL;
        }
    }
    for (int i = 0; i < packet.header->NSCOUNT; i++) {
        if (packet.authority[i].rdata != NULL) {
            free(packet.authority[i].rdata);
            packet.authority[i].rdata = NULL;
        }
    }
    for (int i = 0; i < packet.header->ARCOUNT; i++) {
        if (packet.additional[i].rdata != NULL) {
            free(packet.additional[i].rdata);
            packet.additional[i].rdata = NULL;
        }
    }
    free(packet.answer);
    free(packet.question);
    free(packet.authority);
    free(packet.additional);
}

/**
 * 打印DNS包信息
 */
void DNSPacket_print(DNS_PKT *packet) {
    /*Transaction ID*/
    printf("Transaction ID: 0x%04x\n", packet->header->ID);
    
    /*Flags*/
    /*QR，判断查询或响应*/
    printf(packet->header->QR == QRQUERY ? "Response: Message is a query\n" : "Response: Message is a response\n");
    /*opcode*/
    switch (packet->header->Opcode) {
    case QUERY:
        printf("Opcode: Standard query (0)\n");
        break;
    case IQUERY:
        printf("Opcode: Inverse query (1)\n");
        break;
    case STATUS:
        printf("Opcode: Server status request (2)\n");
        break;
    default:
        break;
    }
    /*AA*/
    if (packet->header->QR == QRRESPONSE) {//若当前报文为响应报文，再判断其是否为权威应答
        printf(packet->header->AA ? "Authoritative: Server is an authority for domain\n" : "Authoritative: Server is not an authority for domain\n");
    }
    /*TC*/
    printf(packet->header->TC ? "Truncated: Message is truncated\n" : "Truncated: Message is not truncated\n");
    /*RD*/
    printf(packet->header->RD ? "Recursion desired: Do query recursively\n" : "Recursion desired: Do not query recursively\n");
    /*RA+Rcode*/
    if (packet->header->QR == QRRESPONSE) {
        //RA标志位只对响应报文有意义。查询报文本身不是最终响应，而是请求，通常不需要关心递归可用性
        printf(packet->header->RA ? "Recursion available: Server can do recursive queries\n" : "Recursion available: Server can not do recursive queries\n");
        switch (packet->header->Rcode) {
        case OK:
            printf("Reply code: No error (0)\n");
            break;
        case FORMERR:
            printf("Reply code: Format error (1)\n");
            break;
        case SERVFAIL:
            printf("Reply code: Server failure (2)\n");
            break;
        case NXDOMAIN:
            printf("Reply code: Name Error (3)\n");
            break;
        case NOTIMP:
            printf("Reply code: Not Implemented (4)\n");
            break;
        case REFUSED:
            printf("Reply code: Refused (5)\n");
            break;
        default:
            break;
        }
    }
    /*count*/
    printf("Questions: %d\n", packet->header->QDCOUNT);
    printf("Answer RRs: %d\n", packet->header->ANCOUNT);
    printf("Authority RRs: %d\n", packet->header->NSCOUNT);
    printf("Additional RRs: %d\n", packet->header->ARCOUNT);
    /*Queries*/
    for (int i = 0; i < packet->header->QDCOUNT; i++) {
        printf("Question %d:\n", i + 1);
        printf("\tName: %s\n", packet->question[i].name);
        /*type*/
        switch (packet->question[i].Qtype) {
        case A:
            printf("\tType: A (1)\n");
            break;
        case NS:
            printf("\tType: NS (2)\n");
            break;
        case CNAME:
            printf("\tType: CNAME (5)\n");
            break;
        case SOA:
            printf("\tType: SOA (6)\n");
            break;
        case NUL:
            printf("\tType: NUL (10)\n");
            break;
        case PTR:
            printf("\tType: PTR (12)\n");
            break;
        case MX:
            printf("\tType: MX (15)\n");
            break;
        case TXT:
            printf("\tType: TXT (16)\n");
            break;
        case AAAA:
            printf("\tType: AAAA (28)\n");
            break;
        case ANY:
            printf("\tType: ANY (256)\n");
            break;
        default:
            break;
        }
        /*class*/
        printf("\tClass: IN (0x0001)\n");
    }
    /*Answers*/
    for (int i = 0; i < packet->header->ANCOUNT; i++) {
        printf("Answer %d:\n", i + 1);
        /*Name*/
        printf("\tName: %s\n", packet->answer[i].name);
        /*Type*/
        switch (packet->answer[i].type) {
        case A:
            printf("\tType: A (1)\n");
            break;
        case NS:
            printf("\tType: NS (2)\n");
            break;
        case CNAME:
            printf("\tType: CNAME (5)\n");
            break;
        case SOA:
            printf("\tType: SOA (6)\n");
            break;
        case NUL:
            printf("\tType: NUL (10)\n");
            break;
        case PTR:
            printf("\tType: PTR (12)\n");
            break;
        case MX:
            printf("\tType: MX (15)\n");
            break;
        case TXT:
            printf("\tType: TXT (16)\n");
            break;
        case AAAA:
            printf("\tType: AAAA (28)\n");
            break;
        case ANY:
            printf("\tType: ANY (256)\n");
            break;
        default:
            break;
        }
        /*Class*/
        printf("\tClass: IN (0x0001)\n");
        /*Time to live*/
        printf("\tTime to live: %d\n", packet->answer[i].TTL);
        /*Data length*/
        printf("\tData length: %d\n", packet->answer[i].rdlength);
        char res[256];
        switch (packet->answer[i].type) {
        case A:
            inet_ntop(AF_INET, packet->answer[i].rdata, res, 256);
            printf("\tAddress: %s\n", res);
            break;
        case AAAA:
            inet_ntop(AF_INET6, packet->answer[i].rdata, res, 256);
            printf("\tAAAA Address: %s\n", res);
            break;
        case CNAME:
            printf("\tCNAME: %s\n", packet->answer[i].rdataName);
            break;
        case NS:
            printf("\tNS: %s\n", packet->answer[i].rdataName);
            break;
        case PTR:
            printf("\tPTR: %s\n", packet->answer[i].rdataName);
            break;
        case TXT:
            printf("\tTXT length: %d\n", (unsigned char)packet->answer[i].rdata[0]);
            printf("\tTXT: %s\n", packet->answer[i].rdata + 1);
            break;
        default:
            printf("\tNot A or AAAA or CNAME: ");
            for (int i = 0; i < packet->answer[i].rdlength; i++) {
                printf("%x", packet->answer[i].rdata[i]);
            }
            printf("\n");
        }
    }
    printf("\n");
}

/**
 * 生成回应包
 */
DNS_PKT prepare_answerPacket(uint32_t ip)
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
    if (dnspacket.header->QR!= QRQUERY || dnspacket.header->QDCOUNT != 1) {//若dnspacket不是一个查询类型的 DNS 报文或者其问题字段不是一个问题
        DNSPacket_destroy(dnspacket); //销毁packet，解除内存占用
        return;
    }
    uint32_t target_ip;
    //拦截不良网站
    if(trie_search(dnspacket.question->name, &target_ip))
    {
        DNS_PKT answer_Packet=prepare_answerPacket(target_ip);
        if(runtime->config.debug){//输出调试信息
            printf("Send packet back to client %s:%d\n",inet_ntoa(client_Addr.sin_addr), ntohs(client_Addr.sin_port));
            DNSPacket_print(&answer_Packet);
            runtime->totalCount++;
            printf("Domain name blocked!\n");
            printf("TOTAL COUNT %d\n", runtime->totalCount);
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
    //先在本地cache中搜索
    if(IsCacheable(dnspacket.question->Qtype)){
        bool find_result=cache_search(dnspacket.question->name,&target_ip);
        if(find_result){//若在cache中查询到了结果
            if(runtime->config.debug){//打印debug信息
                printf("Cache Hint! Expected ip is %d",target_ip);
            }
            DNS_PKT answer_Packet=prepare_answerPacket(target_ip);
            if(runtime->config.debug){//输出调试信息
                printf("Send packet back to client %s:%d\n",inet_ntoa(client_Addr.sin_addr), ntohs(client_Addr.sin_port));
                DNSPacket_print(&answer_Packet);
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
    Buffer buffer = makeBuffer(DNS_PACKET_SIZE);// 创建一个缓冲区，用于存放将来发送的包的数据
    int status = 0;
    DNS_PKT packet = recvPacket(runtime, runtime->client, &buffer, &runtime->upstream_addr, &status);
    if (status <= 0) {
        // 接收失败 ———— 空包，甚至不需要destroy。
        free(buffer.data);
        return;
    }
    IdMap client = getIdMap(runtime->idmap, packet.header->ID);// 这步是？
    packet.header->ID = client.originalId;// 还原id
    /*将接收到的上游应答 发送回客户端*/
    if (runtime->config.debug) {
        char clientIp[16];
        inet_ntop(AF_INET, &client.addr.sin_addr, clientIp, sizeof(clientIp));
        printf("C<< Send packet back to client %s:%d\n", clientIp, ntohs(client.addr.sin_port));
        DNSPacket_print(&packet);
        runtime->totalCount++;
        printf("TOTAL COUNT %d\n", runtime->totalCount);
    }// 需要的话，输出调试信息
    Buffer buffer_tmp;
    buffer_tmp = DNSPacket_encode(packet);// 将上游响应的DNS报文转换为buffer
    for (int i = 0; i < 16; i++) {
        buffer.data[i] = buffer_tmp.data[i];// 将上游响应的数据内容存入发送缓冲区
    }
    free(buffer_tmp.data);
    status = sendto(runtime->server, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&client.addr, sizeof(client.addr));
    if (status < 0) {//为什么不是status < buffer.length？
        printf("Error sendto: %d\n", WSAGetLastError());
    }
    /*判断是否应该缓存*/
    int shouldCache = 1;
    if (packet.header->Rcode != OK || !checkCacheable(packet.question->Qtype) || packet.header->ANCOUNT < 1) {
        shouldCache = 0;// 若在查询中指定域名不存在，或不可checkCache，或上游服务器应答中answer数量<1，则不缓存
    }
    if (shouldCache) {
        // 进缓存
        Key cacheKey;
        cacheKey.qtype = packet.question->Qtype;
        strcpy_s(cacheKey.name, 256, packet.question->name);//为什么不用strcpy？// 把上游响应的域名设为Cache关键字
        MyData cacheItem;
        cacheItem.time = time(NULL);
        cacheItem.answerCount = packet.header->ANCOUNT;
        cacheItem.answers = (DNS_RECORD *)malloc(sizeof(DNS_RECORD) * packet.header->ANCOUNT);
         /*准备缓存项*/
        for (uint16_t i = 0; i < packet.header->ANCOUNT; i++) {
            DNS_RECORD *newRecord = &cacheItem.answers[i];
            DNS_RECORD *old = &packet.answer[i];
            newRecord->TTL = old->TTL;
            newRecord->type = old->type;
            newRecord->addr_class = old->addr_class;
            strcpy_s(newRecord->name, 256, old->name);
            if (strlen(old->name)) {
                newRecord->rdata = (char *)malloc(sizeof(char) * 256);
                strcpy_s(newRecord->name, 256, old->name);
                toQname(old->name, newRecord->rdata);
                newRecord->rdlength = (uint16_t)strnlen_s(newRecord->rdata, 256) + 1;
            } else {
                newRecord->rdlength = old->rdlength;
                newRecord->rdata = (char *)malloc(sizeof(char) * newRecord->rdlength);
                memcpy(newRecord->rdata, old->rdata, newRecord->rdlength);
                newRecord->name[0] = '\0';
            }
        }
        //lRUCachePut(runtime->Cache, cacheKey, cacheItem); //写入缓存
        writeCache(runtime->config.cachefile, runtime);   //保存cache文件
        if (runtime->config.debug) {
            printf("ADDED TO CACHE\n");
        }
    }
    if (runtime->config.debug) {
        //printf("CACHE SIZE %d\n", runtime->Cache->size);
    }
    // 用完销毁
    free(buffer.data);
    DNSPacket_destroy(packet);
}

/**
 * 循环处理用户请求
 */
void loop(DNS_RUNTIME* runtime) {
    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(runtime->server, &readfds);
        FD_SET(runtime->client, &readfds);
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        int ready = select(0, &readfds, NULL, NULL, &tv);
        if (runtime->quit == 1) {
            return;
        }
        if (ready == -1) {
            printf("Error in select\n");
        } else if (ready == 0) {
            printf("Timeout occurred!\n");
        } else {
            if (FD_ISSET(runtime->server, &readfds)) {
                HandleFromClient(runtime);
            }
            if (FD_ISSET(runtime->client, &readfds)) {
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
    /* Questions */
    packet.questions = (DNSQuestion *)malloc(sizeof(DNSQuestion) * packet.header.questionCount);
    for (int i = 0; i < packet.header.questionCount; i++) {
        DNSQuestion *r = &packet.questions[i];
        data += decodeQname((char *)data, (char *)buffer->data, r->name);
        if (data > buffer->data + buffer->length) {
            buffer->length = 0;
            free(packet.questions);
            return packet;
        }
        uint16_t tmp;
        data = _read16(data, &tmp);
        if (data > buffer->data + buffer->length) {
            buffer->length = 0;
            free(packet.questions);
            return packet;
        }
        r->qtype = (DNSQType)tmp;
        data = _read16(data, &tmp);
        if (data > buffer->data + buffer->length) {
            buffer->length = 0;
            free(packet.questions);
            return packet;
        }
        r->qclass = (DNSQClass)tmp;
    }
    /* Answers */
    if (packet.header> 0) {
        packet.answer = (DNSRecord *)malloc(sizeof(DNSRecord) * packet.header.answerCount);
        for (int i = 0; i < packet.header->ANCOUNT; i++) {
            data += decodeQname((char *)data, (char *)buffer->data, packet.answer[i].name);
            if (data > buffer->data + buffer->length) {
                buffer->length = 0;
                free(packet.question);
                for (int j = 0; j < i; j++) {
                    free(packet.answer[i].rdata);
                }
                free(packet.answer);
                return packet;
            }
            uint16_t tmp;
            data = _read16(data, &tmp);
            if (data > buffer->data + buffer->length) {
                buffer->length = 0;
                free(packet.question);
                for (int j = 0; j < i; j++) {
                    free(packet.answer[i].rdata);
                }
                free(packet.answer);
                return packet;
            }
            r->type = (DNSQType)tmp;
            data = _read16(data, &tmp);
            if (data > buffer->data + buffer->length) {
                buffer->length = 0;
                free(packet.question);
                for (int j = 0; j < i; j++) {
                    free(packet.answer[i].rdata);
                }
                free(packet.answer);
                return packet;
            }
            r->rclass = (DNSQClass)tmp;
            data = _read32(data, &r->ttl);
            if (data > buffer->data + buffer->length) {
                buffer->length = 0;
                free(packet.question);
                for (int j = 0; j < i; j++) {
                    free(packet.answer[i].rdata);
                }
                free(packet.answer);
                return packet;
            }
            data = _read16(data, &r->rdataLength);
            if (data > buffer->data + buffer->length) {
                buffer->length = 0;
                free(packet.question);
                for (int j = 0; j < i; j++) {
                    free(packet.answer[i].rdata);
                }
                free(packet.answer);
                return packet;
            }
            r->rdata = (char *)malloc(sizeof(char) * r->rdataLength);
            memcpy(r->rdata, data, r->rdataLength);
            switch (r->type) {
            case NS:
            case CNAME:
            case PTR: {
                decodeQname((char *)data, (char *)buffer->data, r->rdataName);
                break;
            }
            default: {
                strcpy_s(r->rdataName, 256, "");
                break;
            }
            }
            data += r->rdataLength;
        }
    } else {
        packet.answer = NULL;
}

/**
 * 实现DNS包向buffer的转换
 */
Buffer DNSPacket_encode(DNS_PKT packet) {
    Buffer buffer = makeBuffer(DNS_PACKET_SIZE);
    uint8_t *data = buffer.data;
    /* Header */
    data = _write16(data, packet.header->ID);
    /* QR+OP+AA+TC+RD */
    data = _write8(data,packet.header->QR << 7 |
                       packet.header->Opcode << 3 |
                       packet.header->AA << 2 |
                       packet.header->TC << 1 |
                       packet.header->RD << 0);
    /* RA+padding(3)+RCODE */
    data = _write8(data, packet.header->RA << 7 | packet.header->Rcode);
    /* Counts */
    data = _write16(data, packet.header->QDCOUNT);
    data = _write16(data, packet.header->ANCOUNT);
    data = _write16(data, packet.header->NSCOUNT);
    data = _write16(data, packet.header->ARCOUNT);
    /* Questions */
    for (int i = 0; i < packet.header->QDCOUNT; i++) {
        data += toQname(packet.question[i].name, (char *)data);
        data = _write16(data, packet.question[i].Qtype);
        data = _write16(data, packet.question[i].Qclass);
    }
    /* Answers */
    for (int i = 0; i < packet.header->ANCOUNT; i++) {
        data += toQname(packet.answer[i].name, (char *)data);
        data = _write16(data, packet.answer[i].type);
        data = _write16(data, packet.answer[i].addr_class);
        data = _write32(data, packet.answer[i].TTL);
        data = _write16(data, packet.answer[i].rdlength);
        memcpy(data, packet.answer[i].rdata, packet.answer[i].rdlength);
        data += packet.answer[i].rdlength;
    }
    /* Authorities */
    for (int i = 0; i < packet.header->NSCOUNT; i++) {
        data += toQname(packet.authority[i].name, (char *)data);
        data = _write16(data, packet.authority[i].type);
        data = _write16(data, packet.authority[i].addr_class);
        data = _write32(data, packet.authority[i].TTL);
        data = _write16(data, packet.authority[i].rdlength);
        memcpy(data, packet.authority[i].rdata, packet.authority[i].rdlength);
        data += packet.authority[i].rdlength;
    }
    /* Additional */
    for (int i = 0; i < packet.header->ARCOUNT; i++) {
        data += toQname(packet.additional[i].name, (char *)data);
        data = _write16(data, packet.additional[i].type);
        data = _write16(data, packet.additional[i].addr_class);
        data = _write32(data, packet.additional[i].TTL);
        data = _write16(data, packet.additional[i].rdlength);
        memcpy(data, packet.additional[i].rdata, packet.additional[i].rdlength);
        data += packet.additional[i].rdlength;
    }
    buffer.length = (uint32_t)(data - buffer.data);
    return buffer;
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