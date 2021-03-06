#ifndef HTTP_PROXY_H
#define HTTP_PROXY_H

#include <netinet/in.h>
#include <sys/epoll.h>
#include <time.h>
#include "main.h"

#define CONNECT_HEADER "CONNECT [H] HTTP/1.1\r\n\r\n"

/* 数据类型 */
#define OTHER 1
#define HTTP 2
#define HTTP_OTHERS 3
#define HTTP_CONNECT 4
/* 处理TCP请求模式 */
#define WAP 1
#define WAP_CONNECT 2
#define NET_CONNECT 3
#define NET_PROXY 4

struct ssl_string {
    char *str;
    struct ssl_string *next;
};

typedef struct connection {
    struct sockaddr_in original_dst;
    char *ready_data; //已就绪的数据，可以发送
    char *incomplete_data; //存放不是完整的请求头
    char *host;
    char *connect; //存放CONNECT请求
    int connect_len; //CONNECT请求的长度
    int incomplete_data_len, ready_data_len, sent_len, fd, timer;
    uint16_t original_port;
    unsigned reqType :3, //请求类型
        first_connection :1, //发送客户端数据前是否首先进行CONNECT连接
        is_httpsProxy :1;  //如果真 则表示连接是走HTTPS模块
} tcp_t;

extern void tcp_timeout_check();
extern int tcp_listen(char *ip, int port);
extern void tcp_init();
extern void tcp_loop();
extern int8_t make_ssl(tcp_t *client);
extern uint8_t request_type(char *req);

extern struct ssl_string *ssl_str;
extern uint16_t tcp_listen_port;

#endif
