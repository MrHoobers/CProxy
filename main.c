#include <dirent.h>
#include <pthread.h>
#include "main.h"

#define SERVICE_TYPE_STOP 1
#define SERVICE_TYPE_STATUS 2
#define SERVICE_TYPE_STATUS_NOT_PRINT 3

struct global global;

static char *get_proc_name(char *path)
{
    char proc_name[257];
    FILE *fp;
    int readsize;

    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;
    readsize = fread(proc_name, 1, 256, fp);
    fclose (fp);
    return strndup(proc_name, readsize - 1);
}

static int8_t additional_service(char *self_name, uint8_t service_type)
{
    char commpath[270];
    DIR *DP;
    struct dirent *dp;
    char *proc_name;
    pid_t self_pid;

    DP = opendir("/proc");
    if (DP == NULL)
        return 1;
    proc_name = strrchr(self_name, '/');
    if (proc_name)
        self_name = proc_name + 1;
    self_pid = getpid();
    while ((dp = readdir(DP)) != NULL)
    {
        if (dp->d_type != DT_DIR)
            continue;
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0 || atoi(dp->d_name) == self_pid)
            continue;
        sprintf(commpath, "/proc/%s/comm", dp->d_name);
        proc_name = get_proc_name(commpath);
        if (proc_name == NULL)
            continue;
        if (strcmp(proc_name, self_name) == 0)
        {
            if (service_type == SERVICE_TYPE_STOP)
                kill(atoi(dp->d_name), SIGTERM);
            else
            {
                free(proc_name);
                closedir(DP);
                if (service_type != SERVICE_TYPE_STATUS_NOT_PRINT)
                    printf("✔  %s(" VERSION ") 正在运行\n", self_name);
                return 0;
            }
        }
        free(proc_name);
    }
    closedir(DP);

    if (service_type == SERVICE_TYPE_STATUS)
        printf("✘  %s(" VERSION ") 没有运行\n", self_name);
    else if (service_type == SERVICE_TYPE_STATUS_NOT_PRINT)
        return 1;
    return 0;
}

void *timeout_check(void *nullPtr)
{
    while (1)
    {
        sleep(60);
        if (global.tcp_listen_fd >= 0)
            tcp_timeout_check();
        if (global.dns_listen_fd >= 0)
            dns_timeout_check();
        if (global.udp_listen_fd >= 0)
            udp_timeout_check();
    }

    return NULL;
}

/* 初始化变量 */
static void initVariable()
{
    memset(&global, 0, sizeof(global));
    memset(&http, 0, sizeof(http));
    memset(&https, 0, sizeof(https));
    memset(&httpdns, 0, sizeof(httpdns));
    memset(&udp, 0, sizeof(udp));
    saveHdrs = NULL;
    http.dst.sin_family = https.dst.sin_family = httpdns.dst.sin_family = udp.dst.sin_family = AF_INET;
    global.tcp_listen_fd = global.dns_listen_fd = global.udp_listen_fd = global.uid = -1;
}

static void handle_cmd(int argc, char **argv)
{
    /* 命令行选项 */
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
    {
        puts("ChameleonProxy(" VERSION ")\n"
        "Author: 萌萌逼\n"
        "启动命令:\n    CProxy CProxy.conf\n"
        "结束命令:\n    CProxy stop\n"
        "检测命令:\n    CProxy status\n"
        "重启命令:\n    CProxy restart CProxy.conf\n");
        exit(argc < 2 ? 1 : 0);
    }
    if (strcasecmp(argv[1], "stop") == 0)
        exit(additional_service(argv[0], SERVICE_TYPE_STOP));
    else if (strcasecmp(argv[1], "status") == 0)
        exit(additional_service(argv[0], SERVICE_TYPE_STATUS));
    else if (strcasecmp(argv[1], "restart") == 0)
    {
        additional_service(argv[0], SERVICE_TYPE_STOP);
        while (additional_service(argv[0], SERVICE_TYPE_STATUS_NOT_PRINT) == 0);
        argv++;
    }
    read_conf(argv[1]);
}

static void server_init()
{
    /* 忽略PIPE信号 */
    signal(SIGPIPE, SIG_IGN);
    //不能用setgid和setuid，这两个函数不能切换回root，可能导致HTTPUDP代理失败
    if (global.uid > -1 && (setegid(global.uid) == -1 || seteuid(global.uid) == -1))
    {
        perror("setegid(or seteuid)");
        exit(1);
    }
    #ifndef DEBUG
    if (daemon(1, 1) == -1)
    {
        perror("daemon");
        exit(1);
    }
    #endif
    /*
    一个进程只开一个子进程，
    程序结束时子进程先写入dns缓存，
    之后主进程再写入，
    否则可能导致缓存文件格式错误
    */
    while (global.procs-- > 1 && (child_pid = fork()) == 0);
}

static void start_server_loop()
{
    pthread_t thread_id;

    if (global.timeout_m)
        pthread_create(&thread_id, NULL, &timeout_check, NULL);
    if (global.tcp_listen_fd >= 0)
    {
        tcp_init();  //必须在此处先初始化   否则可能DNS或者UDP初始化生成不了CONNECT请求
        if (saveHdrs)
            pthread_create(&thread_id, NULL, &save_header_timer, NULL);
        if (global.dns_listen_fd >= 0)
        {
            dns_init();
            pthread_create(&thread_id, NULL, &dns_loop, NULL);
        }
        if (global.udp_listen_fd >= 0)
        {
            udp_init();
            pthread_create(&thread_id, NULL, &udp_loop, NULL);
        }
        tcp_loop();
    }
    if (global.dns_listen_fd >= 0)
    {
        dns_init();
        if (global.udp_listen_fd >= 0)
        {
            udp_init();
            pthread_create(&thread_id, NULL, &udp_loop, NULL);
        }
        dns_loop(NULL);
    }
    udp_init();
    udp_loop(NULL);
}

int main(int argc, char *argv[])
{
    initVariable();
    handle_cmd(argc, argv);
    server_init();
    start_server_loop();

    return 0;
}



