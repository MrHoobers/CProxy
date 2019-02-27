#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "main.h"
#include <regex.h>

/* 请求头修改操作 */
#define SET_FIRST 1
#define DEL_HDR 2
#define REGREP 3
#define STRREP 4
#define SAVE_HDR 5

struct http_request {
    int other_len, header_len;
    char *header, *other, *method, *url, *uri, *host, version[8];
};
struct save_header {
    struct save_header *next;
    char *key, *value, *replace_string;
    int key_len, value_len, replace_string_len, updateTime, timer;
    unsigned notUpdate :1;
};
struct modify {
    char *first, *del_hdr, *src, *dest;
    struct save_header *saveHdr;
    struct modify *next;
    int first_len, del_hdr_len, src_len, dest_len;
    unsigned flag :3; //判断修改请求头的操作
};
struct tcp_mode {
    struct sockaddr_in dst;
    struct modify *m;
    unsigned encodeCode,  //wap_connect模式数据编码传输
        uri_strict :1,
        http_only_get_post :1;
};

extern void *save_header_timer(void *nullPtr);
extern int8_t modify_request();

extern struct tcp_mode http, https;
extern struct save_header *saveHdrs;
extern int  default_ssl_request_len, original_default_ssl_request_len;
extern char * default_ssl_request, *original_default_ssl_request;

#endif