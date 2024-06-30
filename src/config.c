#include <stdio.h>
#include "config.h"
#include "resource.h"
#define MAXCACHE 1024
/* 初始化DNS服务器配置 */
DNS_CONFIG config_init(int argc, char *argv[]) {
    DNS_CONFIG config;
    config.block_list = FALSE;
    config.debug = FALSE;
    config.port = 53;
    // 默认上游服务器IP
    strcpy(config.upstream_server_IP, "10.3.9.4");

    for (int i = 0; i < argc; i++) {
        if (strcmp("-u", argv[i]) == 0) {
            // 设定上游服务器IP
            strcpy(config.upstream_server_IP, argv[i+1]);
        }
        else if (strcmp("-b", argv[i]) == 0) {
            // 设定有blocklist
            config.block_list = TRUE;
        }
        else if (strcmp("-d", argv[i]) == 0) {
            // 开启debug模式
            config.debug = TRUE;
        }
    }
    return config;
}

DNS_RUNTIME runtime_init(DNS_CONFIG *config) {
    DNS_RUNTIME runtime;
    runtime.config = *config;
    runtime.quit = FALSE;
    runtime.idmap = initIdMap();
    runtime.maxId = 0;
    runtime.totalCount = 0;
    return runtime;
}

/* IDMap的初始化 */
IdMap *initIdMap(){
    IdMap *idmap = (IdMap *)malloc(sizeof(IdMap) * (MAXID + 1)); // 为0-65535共65536个id的IdMap分配空间
    for(int i=0; i <= MAXID; i++){
        idmap[i].time = 0; // 把每一个id的过期时间初始化为0
    }
    return idmap;
}
