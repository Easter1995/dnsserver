#include <stdio.h>
#include "config.h"
#include "resource.h"
#define MAXCACHE 1024

/**
 * 初始化DNS服务器配置
 */
DNS_CONFIG config_init(int argc, char *argv[])
{
    DNS_CONFIG config;
    config.debug = FALSE;
    config.port = 53;
    // 默认上游服务器IP
    strcpy(config.upstream_server_IP, "10.3.9.5");

    for (int i = 0; i < argc; i++)
    {
        if (strcmp("-u", argv[i]) == 0)
        {
            // 设定上游服务器IP
            strcpy(config.upstream_server_IP, argv[i + 1]);
        }
        else if (strcmp("-d", argv[i]) == 0)
        {
            // 开启debug模式
            config.debug = TRUE;
        }
        else if (strcmp("-dd", argv[i]) == 0)
        {
            // 开启二级debug模式
            config.debug = TRUE;
            config.debug_2 = TRUE;
        }
    }
    return config;
}

/**
 * 运行时初始化
 */
DNS_RUNTIME runtime_init(DNS_CONFIG *config)
{
    DNS_RUNTIME runtime;
    runtime.config = *config;
    runtime.quit = FALSE;
    runtime.idmap = initIdMap();
    runtime.maxId = 0;
    return runtime;
}

/**
 * 运行时销毁
 */
void destroyRuntime(DNS_RUNTIME *runtime)
{
    if (runtime->quit > 0)
    {
        // 退出已经处理完成了，无需再处理
        return;
    }
    runtime->quit = 1;
    closesocket(runtime->server);
    closesocket(runtime->client);
    free(runtime->idmap);
}