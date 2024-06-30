#include "handler.h"

/**
 * 初始化socket
 */
void socket_init(DNS_RUNTIME *runtime)
{
    WSADATA wsa_data;
    // 使用winsock2.2版本
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        printf("ERROR: WSAStartup failed\n");
        exit(-1);
    }

    uint16_t default_port = 53;

    // 监听请求的socket
    runtime->server = socket(AF_INET, SOCK_DGRAM, 0);
    if (runtime->server == INVALID_SOCKET)
    {
        printf("ERROR: socket creation failed\n");
        WSACleanup();
        exit(-1);
    }

    const int REUSE = 1;
    if (setsockopt(runtime->server, SOL_SOCKET, SO_REUSEADDR, (const char *)&REUSE, sizeof(REUSE)) < 0)
    {
        printf("ERROR: setsockopt failed\n");
        closesocket(runtime->server);
        WSACleanup();
        exit(-1);
    }

    // 初始化本机服务器地址
    runtime->listen_addr.sin_family = AF_INET;                   // 使用IPv4
    runtime->listen_addr.sin_addr.s_addr = INADDR_ANY;           // 监听所有本地网络接口的传入数据
    runtime->listen_addr.sin_port = htons(runtime->config.port); // 使用配置中指定的端口

    if (bind(runtime->server, (struct sockaddr *)&runtime->listen_addr, sizeof(runtime->listen_addr)) < 0)
    {
        printf("ERROR: bind failed: %d\n", WSAGetLastError());
        closesocket(runtime->server);
        WSACleanup();
        exit(-1);
    }

    // 发出请求的socket
    runtime->client = socket(AF_INET, SOCK_DGRAM, 0);
    if (runtime->client == INVALID_SOCKET)
    {
        printf("ERROR: socket creation failed\n");
        closesocket(runtime->server);
        WSACleanup();
        exit(-1);
    }

    // 初始化上游服务器的地址
    runtime->upstream_addr.sin_family = AF_INET;           // 使用IPv4
    runtime->upstream_addr.sin_port = htons(default_port); // 默认使用53号端口

    // 将点分十进制形式的 IP 地址转换为网络字节序的二进制形式
    struct sockaddr_in sa;
    int sa_len = sizeof(sa);
    if (WSAStringToAddressA(runtime->config.upstream_server_IP, AF_INET, NULL, (struct sockaddr *)&sa, &sa_len) != 0)
    {
        printf("ERROR: WSAStringToAddressA failed\n");
        closesocket(runtime->server);
        closesocket(runtime->client);
        WSACleanup();
        exit(-1);
    }
    runtime->upstream_addr.sin_addr = sa.sin_addr;

    printf("Accepting connections ...\n");
}

/**
 * “消费者”函数
 * 任务是从请求队列里面取出一个请求并处理这个请求
 * 解码DNS包
 * 查看cache是否命中，未命中向上游服务器发出请求
 */
unsigned __stdcall worker_thread(void *arg)
{
    DNS_RUNTIME *runtime = (DNS_RUNTIME *)arg; // 获取运行时
    while (1)
    {
        // 等待任务或者关闭事件
        HANDLE events[] = {thread_pool.cond, thread_pool.shutdown_event};
        DWORD wait_result = WaitForMultipleObjects(2, events, FALSE, INFINITE);

        printf("worker_thread start\n");

        if (wait_result == WAIT_OBJECT_0 + 1)
        {
            // 第二个句柄触发，收到关闭事件，退出线程
            return 0;
        }

        Request *request = dequeue_task(&thread_pool.request_queue); // 获取请求
        if (request)
        {
            printf("request received\n");
            struct sockaddr_in client_Addr = request->client_addr; // 获取客户端地址
            Buffer buffer = request->buffer;                       // 获取数据缓冲区
            DNS_PKT dnspacket = request->dns_packet;               // 获取接收到的dns包

            // 处理请求的逻辑
            if (dnspacket.header->QR != QRQUERY || dnspacket.header->QDCOUNT != 1)
            {                                 // 若dnspacket不是一个查询类型的 DNS 报文或者其问题字段不是一个问题
                DNSPacket_destroy(dnspacket); // 销毁packet，解除内存占用
                return 0;
            }
            if (dnspacket.question->Qtype == 1)
            { // 只有当请求的资源类型为ipv4时，服务器做出回应
                uint32_t wrong_ip[1];
                // 拦截不良网站
                if (trie_search(dnspacket.question->name, &wrong_ip[0]))
                {
                    DNS_PKT answer_Packet = prepare_answerPacket(wrong_ip, dnspacket, 1);
                    if (runtime->config.debug)
                    { // 输出调试信息
                        printf("Send packet back to client %s:%d\n", inet_ntoa(client_Addr.sin_addr), ntohs(client_Addr.sin_port));
                        DNSPacket_print(&answer_Packet);
                        runtime->totalCount++;
                        printf("Domain name blocked!\n");
                        printf("TOTAL COUNT %d\n", runtime->totalCount);
                    }
                    answer_Packet.header->RA = 1;
                    buffer = DNSPacket_encode(answer_Packet); // 将DNS包转换为buffer，方便发送
                    DNSPacket_destroy(answer_Packet);
                    int sendBytes = sendto(runtime->server, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&client_Addr, sizeof(sizeof(client_Addr))); // 由服务器发给客户端找到的ip信息
                    free(buffer.data);                                                                                                                            // 数据发送完后释放缓存
                    if (sendBytes == SOCKET_ERROR)
                    {
                        printf("sendto failed: %d\n", WSAGetLastError());
                        WSACleanup();
                    }
                    else
                        printf("Sent %d bytes to server.\n", sendBytes);
                    return 0;
                }
                // 先在本地cache中搜索
                int actual_ip_cnt = 0;
                uint32_t target_ip[MAX_IP_COUNT];
                bool find_result = cache_search(dnspacket.question->name, target_ip, &actual_ip_cnt);
                if (find_result)
                { // 若在cache中查询到了结果
                    DNS_PKT answer_Packet = prepare_answerPacket(target_ip, dnspacket, actual_ip_cnt);
                    if (runtime->config.debug)
                    { // 输出调试信息
                        printf("Send packet back to client %s:%d\n", inet_ntoa(client_Addr.sin_addr), ntohs(client_Addr.sin_port));
                        DNSPacket_print(&answer_Packet);
                        runtime->totalCount++;
                        printf("TOTAL COUNT %d\n", runtime->totalCount);
                        printf("CACHE SIZE %d\n", cache_list.list_size);
                    }
                    answer_Packet.header->RA = 1;
                    buffer = DNSPacket_encode(answer_Packet); // 将DNS包转换为buffer，方便发送
                    DNSPacket_destroy(answer_Packet);
                    int sendBytes = sendto(runtime->server, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&client_Addr, sizeof(sizeof(client_Addr))); // 由服务器发给客户端找到的ip信息
                    free(buffer.data);                                                                                                                            // 数据发送完后释放缓存
                    if (sendBytes == SOCKET_ERROR)
                    {
                        printf("sendto failed: %d\n", WSAGetLastError());
                        WSACleanup();
                    }
                    else
                        printf("Sent %d bytes to server.\n", sendBytes);
                    return 0;
                }
                /*若cache未命中，则需要向上级发送包进一步查询*/
                IdMap mapItem;                             // 声明一个ID转换表
                mapItem.addr = request->client_addr;       // 请求方的地址
                mapItem.originalId = dnspacket.header->ID; // 请求方的ID
                mapItem.time = time(NULL) + IDMAP_TIMEOUT; // 设置该记录的过期时间
                runtime->maxId = setIdMap(runtime->idmap, mapItem, runtime->maxId);
                dnspacket.header->ID = runtime->maxId;
                // 发走
                if (runtime->config.debug)
                {
                    printf("Send packet to upstream\n");
                    DNSPacket_print(&dnspacket);
                }
                buffer = DNSPacket_encode(dnspacket);
                DNSPacket_destroy(dnspacket);
                int status = sendto(runtime->client, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&runtime->upstream_addr, sizeof(runtime->upstream_addr));
                if (status < 0)
                {
                    printf("Error sendto: %d\n", WSAGetLastError());
                }
            }
            free(buffer.data);
            free(request);
        }
    }
    return 0;
}

/**
 * “生产者”函数
 * 任务是监听客户端的请求并接受请求
 * 将请求放入请求队列
 */
void HandleFromClient(DNS_RUNTIME *runtime)
{
    Buffer buffer = makeBuffer(DNS_PACKET_SIZE); // 创建缓冲区
    struct sockaddr_in client_Addr;              // 存储客户端的地址信息(IP + port)
    int status = 0;                              // 存储接收数据包的状态

    DNS_PKT dnspacket = recvPacket(runtime, runtime->server, &buffer, &client_Addr, &status); // 接收数据包
    if (status <= 0)
    {
        free(buffer.data);
        return;
    }

    enqueue_task(client_Addr, dnspacket, buffer); // 将请求放入队列
}

/**
 * 初始化DNS空包
 */
DNS_PKT init_DNSpacket()
{
    DNS_PKT packet;
    packet.header=(DNS_HEADER*)malloc(sizeof(DNS_HEADER));
    packet.header->AA=0;
    packet.header->ID=0;
    packet.header->Opcode=0;
    packet.header->RA=0;
    packet.header->Rcode=0;
    packet.header->RD=0;
    packet.header->TC=0;
    packet.header->Z=0;
    packet.header->QR=0;
    packet.answer = NULL;
    packet.question = NULL;
    packet.additional = NULL;
    packet.authority = NULL;
    packet.header->QDCOUNT = 0;
    packet.header->ANCOUNT = 0;
    packet.header->NSCOUNT = 0;
    packet.header->ARCOUNT = 0;
    return packet; // 返回空包
}

/**
 * 销毁DNS包
 */
void DNSPacket_destroy(DNS_PKT packet)
{
    for (int i = 0; i < packet.header->ANCOUNT; i++)
    {
        if (packet.answer[i].rdata != NULL)
        {
            free(packet.answer[i].rdata);
            packet.answer[i].rdata = NULL;
        }
    }
    for (int i = 0; i < packet.header->NSCOUNT; i++)
    {
        if (packet.authority[i].rdata != NULL)
        {
            free(packet.authority[i].rdata);
            packet.authority[i].rdata = NULL;
        }
    }
    for (int i = 0; i < packet.header->ARCOUNT; i++)
    {
        if (packet.additional[i].rdata != NULL)
        {
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
void DNSPacket_print(DNS_PKT *packet)
{
    /*Transaction ID*/
    printf("Transaction ID: 0x%04x\n", packet->header->ID);

    /*Flags*/
    /*QR，判断查询或响应*/
    printf(packet->header->QR == QRQUERY ? "Response: Message is a query\n" : "Response: Message is a response\n");
    /*opcode*/
    switch (packet->header->Opcode)
    {
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
    if (packet->header->QR == QRRESPONSE)
    { // 若当前报文为响应报文，再判断其是否为权威应答
        printf(packet->header->AA ? "Authoritative: Server is an authority for domain\n" : "Authoritative: Server is not an authority for domain\n");
    }
    /*TC*/
    printf(packet->header->TC ? "Truncated: Message is truncated\n" : "Truncated: Message is not truncated\n");
    /*RD*/
    printf(packet->header->RD ? "Recursion desired: Do query recursively\n" : "Recursion desired: Do not query recursively\n");
    /*RA+Rcode*/
    if (packet->header->QR == QRRESPONSE)
    {
        // RA标志位只对响应报文有意义。查询报文本身不是最终响应，而是请求，通常不需要关心递归可用性
        printf(packet->header->RA ? "Recursion available: Server can do recursive queries\n" : "Recursion available: Server can not do recursive queries\n");
        switch (packet->header->Rcode)
        {
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
    for (int i = 0; i < packet->header->QDCOUNT; i++)
    {
        printf("Question %d:\n", i + 1);
        printf("\tName: %s\n", packet->question[i].name);
        /*type*/
        switch (packet->question[i].Qtype)
        {
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
    for (int i = 0; i < packet->header->ANCOUNT; i++)
    {
        printf("Answer %d:\n", i + 1);
        /*Name*/
        printf("\tName: %s\n", packet->answer[i].name);
        /*Type*/
        switch (packet->answer[i].type)
        {
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
    }
    printf("\n");
}

/**
 * 生成回应包
 */
DNS_PKT prepare_answerPacket(uint32_t *ip, DNS_PKT packet, int ip_count)
{
    packet.answer = (DNS_RECORD *)malloc(sizeof(DNS_RECORD) * ip_count);
    packet.header->ANCOUNT = ip_count;
    packet.header->RA = 1;
    strcpy(packet.answer->name, packet.question->name);
    if (ip[0] == 0)
    {
        packet.header->Rcode = 3;
        packet.answer = NULL;
    }
    else
    {
        packet.header->Rcode = 0;
        packet.header->QR = QRRESPONSE;
        packet.header->ANCOUNT = ip_count;
        for (int i = 0; i < ip_count; i++)
        {
            uint32_t ip_network_order = htonl(ip[i]);

            packet.answer[i].type = 1;
            packet.answer[i].addr_class = 1;
            packet.answer[i].rdlength = 4;
            memcpy(packet.answer[i].rdata, &ip_network_order, sizeof(ip_network_order));
        }   
    }
    return packet;
}

/**
 * 接收DNS包
 */
DNS_PKT recvPacket(DNS_RUNTIME *runtime, SOCKET socket, Buffer *buffer, struct sockaddr_in *client_Addr, int *error)
{
    int client_AddrLength = sizeof(*client_Addr);
    int recvBytes = recvfrom(socket, (char *)buffer->data, buffer->length, 0, (struct sockaddr *)client_Addr, &client_AddrLength);
    DNS_PKT packet = init_DNSpacket();
    if (recvBytes == SOCKET_ERROR)
    { // 若接收包过程出现异常
        printf("recvfrom failed:%d\n", WSAGetLastError());
        *error = -1; // 指示DNS包接收状态为故障
    }
    else
    {                               // 正常接受包
        buffer->length = recvBytes; // 更新buffer长度字段
        *error = recvBytes;         // 给函数调用者的标识
        DNSPacket_decode(buffer, &packet);
        if (buffer->length == 0)
        {
            *error = -2; // 指示接收包为空包
            packet = init_DNSpacket();
        }
    }
    if (runtime->config.debug)
    { // 输出debug信息
        if (socket == runtime->server)
        {
            printf("Received packet from client %s:%d\n", inet_ntoa(client_Addr->sin_addr), ntohs(client_Addr->sin_port));
        }
        else
        {
            printf("Received packet from upstream\n");
        }
    }
    return packet;
}

/**
 * 处理上游应答
 */
void HandleFromUpstream(DNS_RUNTIME *runtime)
{
    Buffer buffer = makeBuffer(DNS_PACKET_SIZE); // 创建一个缓冲区，用于存放将来发送的包的数据
    int status = 0;
    DNS_PKT packet = recvPacket(runtime, runtime->client, &buffer, &runtime->upstream_addr, &status);
    if (status <= 0)
    {
        // 接收失败 ———— 空包，甚至不需要destroy。
        free(buffer.data);
        return;
    }
    IdMap client = getIdMap(runtime->idmap, packet.header->ID); 
    packet.header->ID = client.originalId;                      // 还原id
    /*将接收到的上游应答 发送回客户端*/
    if (runtime->config.debug)
    {
        char clientIp[16]; // Assuming IPv4 address can fit in 16 bytes (xxx.xxx.xxx.xxx\0)
        int clientIpLen = sizeof(clientIp);
        if (WSAAddressToStringA((LPSOCKADDR)&client.addr, sizeof(client.addr), NULL, clientIp, &clientIpLen) != 0)
        {
            printf("ERROR: WSAAddressToStringA failed\n");
            closesocket(runtime->server);
            closesocket(runtime->client);
            WSACleanup();
            exit(-1);
        }

        printf("C<< Send packet back to client %s:%d\n", clientIp, ntohs(client.addr.sin_port));
        DNSPacket_print(&packet);
        runtime->totalCount++;
        printf("TOTAL COUNT %d\n", runtime->totalCount);
    } // 需要的话，输出调试信息
    Buffer buffer_tmp;
    buffer_tmp = DNSPacket_encode(packet); // 将上游响应的DNS报文转换为buffer
    for (int i = 0; i < 16; i++)
    {
        buffer.data[i] = buffer_tmp.data[i]; // 将上游响应的数据内容存入发送缓冲区
    }
    free(buffer_tmp.data);
    status = sendto(runtime->server, (char *)buffer.data, buffer.length, 0, (struct sockaddr *)&client.addr, sizeof(client.addr));
    if (status < 0)
    { // 为什么不是status < buffer.length？
        printf("Error sendto: %d\n", WSAGetLastError());
    }
    /*判断是否应该缓存*/
    int shouldCache = 1;
    if (packet.header->Rcode != OK || packet.question->Qtype != A || packet.header->ANCOUNT < 1)
    {
        shouldCache = 0; // 若在查询中指定域名不存在，或不是IPv4，或上游服务器应答中answer数量<1，则不缓存
    }
    if (shouldCache)
    {
        // 逐个缓存条目
        for (uint16_t i = 0; i < packet.header->ANCOUNT; i++) {
            if(packet.answer[i].type == A) { // 如果回答的类型是ipv4地址
                cache_add_one(packet.answer[i].name, *packet.answer[i].rdata, packet.answer[i].TTL); // 向cache中存储该条域名-ip数据
            }
        }
        if (runtime->config.debug)
        {
            printf("ADDED TO CACHE\n");
        }
    }
    // 用完销毁
    free(buffer.data);
    DNSPacket_destroy(packet);
}


/**
 * 循环处理用户请求
 * 监听和处理两个socket是否有数据可读
 */
void loop(DNS_RUNTIME *runtime)
{
    fd_set readfds;
    while (1)
    {
        FD_ZERO(&readfds);                 // 初始化 readfds，清空文件描述符集合
        FD_SET(runtime->server, &readfds); // 添加 server 到 readfds 中
        FD_SET(runtime->client, &readfds); // 添加 client 到 readfds 中
        struct timeval tv;
        tv.tv_sec = 5; // 设置超时时间为 5 秒
        tv.tv_usec = 0;
        // 检查是否有就绪的文件描述符（即有数据可读）
        int ready = select(0, &readfds, NULL, NULL, &tv);
        if (runtime->quit == 1)
        {
            return;
        }
        if (ready == -1)
        {
            int ready = select(0, &readfds, NULL, NULL, &tv);
            if (runtime->quit == 1) // 程序退出
                return;
            if (ready == -1)
            {
                printf("Error in select\n");
            }
            else if (ready == 0)
            {
                printf("Timeout occurred!\n");
            }
        }
        else
        {
            if (FD_ISSET(runtime->server, &readfds))
            { // 接受请求的socket可读，进行处理
                HandleFromClient(runtime);
            }
            if (FD_ISSET(runtime->client, &readfds))
            { // 与上级连接的socket可读,进行处理
                HandleFromUpstream(runtime);
            }
        }
    }
}

/**
 * 初始化长度为len的buffer
 */
Buffer makeBuffer(int len)
{
    Buffer buffer;
    buffer.data = (uint8_t *)malloc(len * sizeof(uint8_t));
    buffer.length = len;
    return buffer;
}

/**
 * 实现buffer向DNS包的转换
 */
void DNSPacket_decode(Buffer *buffer, DNS_PKT *packet)
{
    uint8_t *Rdata_ptr = buffer->data;
    uint8_t tmp8;
    /*Transaction ID*/
    Rdata_ptr = _read16(Rdata_ptr, &packet->header->ID); // 一次读16位
    /* QR+OP+AA+TC+RD */
    Rdata_ptr = _read8(Rdata_ptr, &tmp8); // 一次读8位
    packet->header->QR = (DNSPacketQR)(tmp8 >> 7 & 0x01);
    packet->header->Opcode = (DNSPacketOP)(tmp8 >> 3 & 0x0F);
    packet->header->AA = tmp8 >> 2 & 0x01;
    packet->header->TC = tmp8 >> 1 & 0x01;
    packet->header->RD = tmp8 >> 0 & 0x01;
    /* RA+padding(3)+RCODE */
    Rdata_ptr = _read8(Rdata_ptr, &tmp8);
    packet->header->RA = tmp8 >> 7 & 0x01;
    packet->header->Rcode = (DNSPacketRC)(tmp8 & 0xF);
    /* Counts */
    Rdata_ptr = _read16(Rdata_ptr, &packet->header->QDCOUNT);
    Rdata_ptr = _read16(Rdata_ptr, &packet->header->ANCOUNT);
    Rdata_ptr = _read16(Rdata_ptr, &packet->header->NSCOUNT);
    Rdata_ptr = _read16(Rdata_ptr, &packet->header->ARCOUNT);
    if (Rdata_ptr > buffer->data + buffer->length)
    {
        buffer->length = 0;
        return packet;
    }
    /* Questions */
    if (packet->header->QDCOUNT > 0) {
        packet->question = (DNS_QUESTION *)malloc(sizeof(DNS_QUESTION) * packet->header->QDCOUNT);
        size_t i;
        if (packet->header->QDCOUNT != 1) // 问题数量大于1
        {
            buffer->length = 0;
            *packet = init_DNSpacket();
            return;
        }
        packet->question[0].name[0] = (char *)malloc((strlen(Rdata_ptr)) * sizeof(char));
        Rdata_ptr = getURL(Rdata_ptr, packet->question[0].name);
        packet->question[0].Qtype = (uint16_t)(Rdata_ptr[0] << 8) + Rdata_ptr[1];
        packet->question[0].Qclass = (uint16_t)(Rdata_ptr[2] << 8) + Rdata_ptr[3];
        Rdata_ptr += 4;
    }
    /* Answers */
    if (packet->header->ANCOUNT>0)
    {
        packet->answer = (DNS_RECORD *)malloc(sizeof(DNS_RECORD) * packet->header->ANCOUNT); // 根据头部记录answer的数量来malloc指定空间
        /*Name*/
        for (int i = 0; i < packet->header->ANCOUNT; i++)
        {
            Rdata_ptr = getURL(Rdata_ptr, packet->answer[i].name);
            /*Type*/
            uint16_t tmp;
            Rdata_ptr = _read16(Rdata_ptr, &tmp);
            packet->answer->type = (DNSQType)tmp;
            /*Class*/
            Rdata_ptr = _read16(Rdata_ptr, &tmp);
            packet->answer[i].addr_class = (uint16_t)tmp;
            /*Time to live*/
            Rdata_ptr = _read32(Rdata_ptr, &packet->answer[i].TTL);
            /*Data length*/
            Rdata_ptr = _read16(Rdata_ptr, &packet->answer[i].rdlength);
            /*data*/
            packet->answer[i].rdata = (char *)malloc(sizeof(char) * packet->answer->rdlength);
            memcpy(packet->answer->rdata, Rdata_ptr, packet->answer->rdlength);
            Rdata_ptr += packet->answer->rdlength;

            if (Rdata_ptr > buffer->data + buffer->length + 1) // 指针越界
            {
                buffer->length = 0;
                *packet = init_DNSpacket();
                return; // 返回一个空包
            }
        }
    }
    else
    {
        packet->answer = NULL;
    }
}

/**
 * 实现DNS包向buffer的转换
 */
Buffer DNSPacket_encode(DNS_PKT packet)
{
    Buffer buffer = makeBuffer(DNS_PACKET_SIZE);
    uint8_t *data = buffer.data;
    /* Header */
    data = _write16(data, packet.header->ID);
    /* QR+OP+AA+TC+RD */
    data = _write8(data, packet.header->QR << 7 |
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
    for (int i = 0; i < packet.header->QDCOUNT; i++)
    {
        data = toQname(packet.question[i].name, (char *)data);
        data = _write16(data, packet.question[i].Qtype);
        data = _write16(data, packet.question[i].Qclass);
    }
    /* Answers */
    for (int i = 0; i < packet.header->ANCOUNT; i++)
    {
        data = toQname(packet.answer[i].name, (char *)data);
        data = _write16(data, packet.answer[i].type);
        data = _write16(data, packet.answer[i].addr_class);
        data = _write32(data, packet.answer[i].TTL);
        data = _write16(data, packet.answer[i].rdlength);
        memcpy(data, packet.answer[i].rdata, packet.answer[i].rdlength);
        data += packet.answer[i].rdlength;
    }
    /* Authorities */
    for (int i = 0; i < packet.header->NSCOUNT; i++)
    {
        data = toQname(packet.authority[i].name, (char *)data);
        data = _write16(data, packet.authority[i].type);
        data = _write16(data, packet.authority[i].addr_class);
        data = _write32(data, packet.authority[i].TTL);
        data = _write16(data, packet.authority[i].rdlength);
        memcpy(data, packet.authority[i].rdata, packet.authority[i].rdlength);
        data += packet.authority[i].rdlength;
    }
    /* Additional */
    for (int i = 0; i < packet.header->ARCOUNT; i++)
    {
        data = toQname(packet.additional[i].name, (char *)data);
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
 * 解析域名（给出点分十进制）
 */
uint32_t *getURL(char *name_ptr, char *res)
{
    int len = strlen(name_ptr); // 计算该域名的长度
    int idx = 0;                // 在dns包内域名字符下标
    int bias = name_ptr[0];     // 决定接下来复制字符数量
    int i = 1;
    while (i < len)
    {
        for (int j = 0; j < bias; j++)
        {
            res[idx] = name_ptr[i];
            idx++;
            i++;
        }
        bias = name_ptr[i]; // 计算该域名下一段的长度
        if (bias == 0 || i >= len)
            break;
        i++;
        res[idx] = '.';
        idx++;
    }
    res[idx] = '\0'; // 字符串结束
    return name_ptr + len + 1;
}

/**
 * 解析域名（将点分十进制换为buffer模式）
 */
uint8_t *toQname(char *name, char *data)
{
    int i, j = 0, length = 0;
    for (i = 0; i < strlen(name); i++)
    {
        if (name[i] == '.')
        {
            data[j] = length;
            length = 0;
            j = i + 1;
        }
        else
        {
            if(name[i]>='A'&&name[i]<='Z')//将域名中大写转小写
                name[i]=name[i]+'a'-'A';
            length++;
            data[i + 1] = name[i];
        }
    }
    return data + strlen(name) + 1;
}
/**
 * 解析数据包时指针的移动和读取指定长度的数据
 */
uint8_t *_read32(uint8_t *ptr, uint32_t *value)
{
    *value = ntohl(*(uint32_t *)ptr);
    return ptr + 4;
}
uint8_t *_write32(uint8_t *ptr, uint32_t value)
{
    *(uint32_t *)ptr = htonl(value);
    return ptr + 4;
}
uint8_t *_read16(uint8_t *ptr, uint16_t *value)
{
    *value = ntohs(*(uint16_t *)ptr);
    return ptr + 2;
}
uint8_t *_write16(uint8_t *ptr, uint16_t value)
{
    *(uint16_t *)ptr = htons(value);
    return ptr + 2;
}
uint8_t *_read8(uint8_t *ptr, uint8_t *value)
{
    *value = *(uint8_t *)ptr;
    return ptr + 1;
}
uint8_t *_write8(uint8_t *ptr, uint8_t value)
{
    *(uint8_t *)ptr = value;
    return ptr + 1;
}

/* 寻找空闲会话id */
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

IdMap getIdMap(IdMap *idMap, uint16_t i)
{
    idMap[i].time = 0; // 归还原来的会话id，把过期时间还原为0
    return idMap[i];   // 返回会话id对应的idMap项
}