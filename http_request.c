#include "http_request.h"

struct tcp_mode http, https;
struct save_header *saveHdrs;
char *default_ssl_request, *original_default_ssl_request;
int  default_ssl_request_len, original_default_ssl_request_len;

/* 保存头域计时器，超时后才更新头域的值 */
void *save_header_timer(void *nullPtr)
{
    struct save_header *ptr;

    while (1)
    {
        sleep(60);
        for (ptr = saveHdrs; ptr; ptr = ptr->next)
        {
            if (ptr->timer == 0)
                ptr->notUpdate = 0;
            else
                ptr->timer--;
        }
    }
}

/* 判断请求类型 */
uint8_t request_type(char *req)
{
    if (strncmp(req, "GET", 3) == 0 || strncmp(req, "POST", 4) == 0)
        return HTTP;
    else if (strncmp(req, "CONNECT", 7) == 0)
        return HTTP_CONNECT;
    else if (strncmp(req, "HEAD", 4) == 0 ||
    strncmp(req, "PUT", 3) == 0 ||
    strncmp(req, "OPTIONS", 7) == 0 ||
    strncmp(req, "MOVE", 4) == 0 ||
    strncmp(req, "COPY", 4) == 0 ||
    strncmp(req, "TRACE", 5) == 0 ||
    strncmp(req, "DELETE", 6) == 0 ||
    strncmp(req, "LINK", 4) == 0 ||
    strncmp(req, "UNLINK", 6) == 0 ||
    strncmp(req, "PATCH", 5) == 0 ||
    strncmp(req, "WRAPPED", 7) == 0)
        return HTTP_OTHERS;
    else
        return OTHER;
}

/* 将ip和端口用:拼接 */
static char *splice_ip_port(struct in_addr ip, uint16_t port)
{
    static char original_ip_port[22], *ip_ptr;

    ip_ptr = (char *)&ip;
    sprintf(original_ip_port, "%u.%u.%u.%u:%u", ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3], port);

    return original_ip_port;
}

/* 替换字符串中的use_hdr语法 */
static void safe_useHdr_replace(char *src, int src_len, char **save_ptr, int *save_len_ptr)
{
    if (src == NULL)
        return;

    struct save_header *sh_p;
    char *new_data, *free_ptr;
    int new_data_len;

    if (copy_new_mem(src, src_len, &new_data) != 0)
        return;
    new_data_len = src_len;
    for (sh_p = saveHdrs; sh_p; sh_p = sh_p->next)
        new_data = replace(new_data, &new_data_len, sh_p->replace_string, sh_p->replace_string_len, sh_p->value, sh_p->value_len);
    if (new_data == NULL)
        return;
    /* 判断防止越界 */
    free_ptr = *save_ptr;
    if (new_data_len > *save_len_ptr)
    {
        *save_ptr = new_data;
        *save_len_ptr = new_data_len;
    }
    else
    {
        *save_len_ptr = new_data_len;
        *save_ptr = new_data;
    }
    free(free_ptr);
}

/* 构建CONNECT请求头 */
int8_t make_ssl(tcp_t *ssl)
{
    char *host;
    int host_len;

    if (ssl->original_port == tcp_listen_port && ssl->host)
    {
        if (strchr(ssl->host, ':') == NULL)
        {
            host = (char *)realloc(ssl->host, strlen(ssl->host) + 4);
            if (host == NULL)
            {
                free(ssl->host);
                return 1;
            }
            ssl->host = host;
            strcat(host, ":80");
        }
        host = ssl->host;
        host_len = strlen(host);
    }
    else
    {
        host = splice_ip_port(ssl->original_dst.sin_addr, ssl->original_port);
        host_len = strlen(host);
    }
    if (https.encodeCode)
        dataEncode(host, host_len, https.encodeCode);
    if (copy_new_mem(default_ssl_request, default_ssl_request_len, &ssl->connect) != 0)
        return 1;
    ssl->connect_len = default_ssl_request_len;
    ssl->connect = replace(ssl->connect, &ssl->connect_len, "[H]", 3, host, host_len);
    if (ssl->connect == NULL)
        return 1;

    return 0;
}

/* 返回状态信息 */
static void rsp_stats_msg(tcp_t *client, char *host)
{
    #define STATUS_RESPONSE_HEADER "HTTP/1.0 200 OK\r\n"\
        "Content-Type: text/plain; charset=utf-8\r\n"\
        "\r\n"\
        "ChameleonProxy(" VERSION ") is running\r\n\r\n"
    tcp_t https;

    write(client->fd, STATUS_RESPONSE_HEADER, sizeof(STATUS_RESPONSE_HEADER) - 1);
    /* 返回http请求头 */
    write(client->fd, "HTTP:\r\n", 7);
    write(client->fd, client->ready_data, client->ready_data_len);
    /* 返回https请求头 */
    write(client->fd, "HTTPS:\r\n", 8);
    https.original_port = tcp_listen_port;
    https.host = host;
    make_ssl(&https) == 0 ? \
        write(client->fd, https.connect, https.connect_len) : \
        write(client->fd, "(null)\r\n\r\n", 10);
    free(https.connect);
    /* 返回httpDNS请求头 */
    write(client->fd, "httpDNS(https):\r\n", 17);
    httpdns.connect_request ? \
        write(client->fd, httpdns.connect_request, httpdns.connect_request_len) : \
        write(client->fd, "(null)\r\n\r\n", 10);
    write(client->fd, "httpDNS(http):\r\n", 16);
    httpdns.http_req ? \
        write(client->fd, httpdns.http_req, httpdns.http_req_len) : \
        write(client->fd, "(null)\r\n\r\n", 10);
    /* 返回httpUDP请求头 */
    write(client->fd, "httpUDP:\r\n", 10);
    udp.http_request ? \
        write(client->fd, udp.http_request, udp.http_request_len) : \
        write(client->fd, "(null)\r\n\r\n", 10);
}

/* 释放http_request结构体占用的内存 */
static void free_http_request(struct http_request *http_req)
{
    free(http_req->header);
    free(http_req->other);
    free(http_req->method);
    free(http_req->url);
    free(http_req->host);
}

/* 关键字替换 */
static char *keywords_replace(char *str, int *str_len, unsigned reqType, struct http_request *http_req)
{
    safe_useHdr_replace(str, *str_len, &str, str_len);
    if (reqType != HTTP_CONNECT)
    {
        str = replace(str, str_len, "[M]", 3, http_req->method, strlen(http_req->method));
        str = replace(str, str_len, "[U]", 3, http_req->uri, strlen(http_req->uri));
        str = replace(str, str_len, "[url]", 5, http_req->url, strlen(http_req->url));
        str = replace(str, str_len, "[V]", 3, http_req->version, 8);
    }
    str = replace(str, str_len, "[H]", 3, http_req->host, strlen(http_req->host));
    str = replace(str, str_len, "[0]", 3, "\0", 1);

    return str;
}


/* 正则表达式字符串替换，str为可用free释放的指针 */
static char *regrep(char *str, int *str_len, const char *src, char *dest, int dest_len)
{
    //修改请求头出问题，不进行代理
    if (!str || !src || !dest)
    {
        free(str);
        return NULL;
    }

    regmatch_t pm[10];
    regex_t reg;
    char child_num[2] = {'\\', '0'}, *p, *real_dest;
    int match_len, real_dest_len, i;

    p = str;
    regcomp(&reg, src, REG_NEWLINE|REG_ICASE|REG_EXTENDED);
    while (regexec(&reg, p, 10, pm, 0) == 0)
    {
        if (copy_new_mem(dest, dest_len, &real_dest) != 0)
        {
            regfree(&reg);
            free(str);
            return NULL;
        }
        real_dest_len = dest_len;
        //不进行不必要的字符串操作
        if (pm[1].rm_so >= 0)
        {
            /* 替换目标字符串中的子表达式 */
            for (i = 1; i < 10 && pm[i].rm_so > -1; i++)
            {
                child_num[1] = i + 48;
                real_dest = replace(real_dest, &real_dest_len, child_num, 2, p + pm[i].rm_so, pm[i].rm_eo - pm[i].rm_so);
                if (real_dest == NULL)
                {
                    regfree(&reg);
                    free(str);
                    return NULL;
                }
            }
        }

        match_len = pm[0].rm_eo - pm[0].rm_so;
        p += pm[0].rm_so;
        //目标字符串不大于匹配字符串则不用分配新内存
        if (match_len >= real_dest_len)
        {
            memcpy(p, real_dest, real_dest_len);
            if (match_len > real_dest_len)
                memmove(p + real_dest_len, p + match_len, *str_len - (p + match_len - str) + 1);  //+1是复制后面的\0
            p += real_dest_len;
            *str_len -= match_len - real_dest_len;
        }
        else
        {
            int diff;
            char *before_end, *new_str;

            diff = real_dest_len - match_len;
            *str_len += diff;
            new_str = (char *)realloc(str, *str_len + 1);
            if (new_str == NULL)
            {
                free(str);
                free(real_dest);
                regfree(&reg);
                return NULL;
            }
            str = new_str;
            before_end = str + pm[0].rm_so;
            p = before_end + real_dest_len;
            memmove(p, p - diff, *str_len - (p - str) + 1);
            memcpy(before_end, real_dest, real_dest_len);
        }
        free(real_dest);
    }

    regfree(&reg);
    return str;
}

/* 在请求头中获取host */
static char *get_host(char *header, unsigned reqType)
{
    char *key, *host, *host_end;

    if (reqType == HTTP_CONNECT)
    {
        host_end = strchr(header + 8, ' ');
        if (host_end == NULL)
            return NULL;
        return strndup(header + 8, host_end - (header + 8));
    }

    host = NULL;
    for (key = strchr(header, '\n'); key++; key = strchr(key, '\n'))
    {
        if (strncasecmp(key, "x-online-host:", 14) == 0)
        {
            host = key + 14;
            break;
        }
        else if (strncasecmp(key, "host:", 5) == 0)
        {
            host = key + 5;
        }
    }
    if (host == NULL)
        return NULL;
    while (*host == ' ')
        host++;
    host_end = strchr(host, '\r');
    return host_end ? strndup(host, host_end - host) : strdup(host);
}

/* 删除请求头中的头域，并更新header_len的值 */
static void del_hdr(char *header, int *header_len, struct modify *head)
{
    struct modify *m;
    char *line_begin, *line_end;

    for (line_begin = memchr(header, '\n', *header_len); line_begin++; line_begin = line_end)
    {
        line_end = memchr(line_begin, '\n', *header_len - (line_begin - header));
        m = head;
        do {
            if (strncasecmp(line_begin, m->del_hdr, m->del_hdr_len) == 0 && line_begin[m->del_hdr_len] == ':')
            {
                if (line_end)
                {
                    memmove(line_begin, line_end + 1, *header_len - ((line_end + 1 - header)));
                    *header_len -= (line_end + 1) - line_begin;
                    header[*header_len] = '\0';
                    //新行前一个字符
                    line_end = line_begin - 1;
                }
                else
                {
                    *header_len = line_begin - header;
                    *line_begin = '\0';
                }
                break;
            }
        } while ((m = m->next) != NULL && m->flag == DEL_HDR);
    }
}

/* 更新struct save_header结构体和httpdns httpudp的请求头 */
static void update_new_hdr(char *header, int header_len, struct save_header *sh_p)
{
    char *line_begin, *line_end, *value;

    for (line_begin = memchr(header, '\n', header_len); line_begin++; line_begin = line_end)
    {
        line_end = memchr(line_begin, '\n', header_len - (line_begin - header));
        if (strncasecmp(line_begin, sh_p->key, sh_p->key_len) == 0 && line_begin[sh_p->key_len] == ':')
        {
            for (value = line_begin + sh_p->key_len + 1; *value == ' '; value++);
            line_end ? (sh_p->value_len = line_end - value - 1) : (sh_p->value_len = strlen(value));
            free(sh_p->value);
            if (copy_new_mem(value, sh_p->value_len, &sh_p->value) != 0)
                return;
            if (sh_p->updateTime > 0)
            {
                sh_p->timer = sh_p->updateTime;
                sh_p->notUpdate = 1;
            }
            safe_useHdr_replace(httpdns.original_http_req, httpdns.original_http_req_len, &httpdns.http_req, &httpdns.http_req_len);
            safe_useHdr_replace(httpdns.original_connect_request, httpdns.original_connect_request_len, &httpdns.connect_request, &httpdns.connect_request_len);
            safe_useHdr_replace(udp.original_http_request, udp.original_http_request_len, &udp.http_request, &udp.http_request_len);
            safe_useHdr_replace(original_default_ssl_request, original_default_ssl_request_len, &default_ssl_request, &default_ssl_request_len);
        }
    }
}

/* 处理http请求头 */
static int http_request_header(char *request, int request_len, tcp_t *client, struct http_request *http_req)
{
    char *p;

    /* 分离请求头和请求数据 */
    http_req->header = request;
    if ((p = strstr(request, "\n\r\n")) != NULL && (http_req->header_len = p + 3 - request) < request_len)
    {
        http_req->other_len = request_len - http_req->header_len;
        http_req->other = (char *)malloc(http_req->other_len + 1);
        if (http_req->other)
        {
            memmove(http_req->other, p + 3, http_req->other_len);
            http_req->other[http_req->other_len] = '\0';
        }
        else
            return 1;
        *(http_req->header + http_req->header_len) = '\0';
    }
    else
    {
        http_req->other_len = 0;
        http_req->header_len = request_len;
    }
    http_req->host = get_host(http_req->header, client->reqType);
    /* 如果请求头中包含Host，则设置Host中的端口为第四层目标端口 */
    if (http_req->host)
    {
        p = strchr(http_req->host, ':');
        if (client->original_port != 0 && client->original_port != (p ? atoi(p + 1) : 80))
        {
            http_req->host = (char *)realloc(http_req->host, p ? (p - http_req->host + 7) : (strlen(http_req->host) + 7));
            if (http_req->host == NULL)
                return 1;
            p ? sprintf(p+1, "%u", client->original_port) : sprintf(http_req->host, "%s:%u", http_req->host, client->original_port);
        }
    }
     //如果请求头中没有Host，则设置为原始IP和端口
    else
        http_req->host = strdup(splice_ip_port(client->original_dst.sin_addr, client->original_port));
    if (client->reqType == HTTP_CONNECT)
    {
        if (https.encodeCode)
        {
            dataEncode(http_req->host, strlen(http_req->host), https.encodeCode);
            dataEncode(http_req->other, http_req->other_len, https.encodeCode);
        }
        return 0;
    }


    /*获取method url version*/
    p = strchr(http_req->header, ' ');
    if (p)
    {
        http_req->method = strndup(http_req->header, p - http_req->header);
        char *cr = strchr(++p, '\r'); //http版本后的\r
        if (cr)
        {
            http_req->url = strndup(p, cr - p - 9);
            memcpy(http_req->version ,cr - 8, 8);
        }
    }

    if (http_req->url)
    {
        if (*http_req->url != '/' && (p = strstr(http_req->url, "//")) != NULL)
        {
            p = strchr(p+2, '/');
            http_req->uri = p ? p : "/";
        }
        else
        {
            http_req->uri = http_req->url;
        }
        if (http.uri_strict)
            for (p = strstr(http_req->uri, "//"); p; p = strstr(p, "//"))
                memmove(p, p+1, strlen(p+1)+1);
    }

    return 0;
}

/*
    修改请求头
   返回值: -1为错误，0为需要代理的请求，1为不需要代理的请求
 */
int8_t modify_request(char *request, int request_len, tcp_t *client)
{
    struct http_request http_req;
    struct modify *mod;
    char *p, *new_header, *first, *src, *dest;
    int first_len, src_len, dest_len;

    if (https.encodeCode && client->reqType != HTTP_CONNECT)
    {
        dataEncode(request, request_len, https.encodeCode);
        client->reqType = OTHER;
    }
    //判断数据类型
    switch(client->reqType)
    {
        case HTTP_OTHERS:
            if (http.http_only_get_post)
            {
                free(request);
                return 1;
            }
            //不禁止其他http请求则进行http处理

        case HTTP:
            mod = http.m;
        break;

        case HTTP_CONNECT:
            mod = https.m;
        break;

        //不是http请求头，直接拼接到client->ready_data
        default:
            if (client->ready_data)
            {
                p = (char *)realloc(client->ready_data, client->ready_data_len + request_len + 1);
                if (p == NULL)
                {
                    free(request);
                    return -1;
                }
                client->ready_data = p;
                memcpy(p + client->ready_data_len, request, request_len);
                client->ready_data_len += request_len;
                free(request);
            }
            else
            {
                client->ready_data = request;
                client->ready_data_len = request_len;
            }
        return 0;
    }
    //解析请求头
    memset((struct http_request *)&http_req, 0, sizeof(http_req));
    if (http_request_header(request, request_len, client, &http_req) != 0)
    {
        free(request);
        return -1;
    }

    while (mod)
    {
        switch (mod->flag)
        {
            case DEL_HDR:
                del_hdr(http_req.header, &http_req.header_len, mod);
                //del_hdr函数连续删除头域一次性操作
                while (mod->next && mod->next->flag == DEL_HDR)
                    mod = mod->next;
            break;

            case SAVE_HDR:
                if (mod->saveHdr->notUpdate == 0)
                    update_new_hdr(http_req.header, http_req.header_len, mod->saveHdr);
            break;

            case SET_FIRST:
                first_len = mod->first_len;
                copy_new_mem(mod->first, first_len, &first);
                first = keywords_replace(first, &first_len, client->reqType, &http_req);
                if (first == NULL)
                    goto error;
                p = memchr(http_req.header, '\n', http_req.header_len);
                if (p == NULL)
                {
                    free(http_req.header);
                    http_req.header = first;
                    http_req.header_len = first_len;
                }
                else
                {
                    p++;
                    if (p - http_req.header >= first_len)
                    {
                        memmove(http_req.header + first_len, p, http_req.header_len - (p - http_req.header) + 1);
                        http_req.header_len -= (p - http_req.header) - first_len;
                    }
                    else
                    {
                        new_header = (char *)malloc(first_len + http_req.header_len - (p - http_req.header) + 1);
                        if (new_header == NULL)
                        {
                            free(first);
                            goto error;
                        }
                        memcpy(new_header + first_len, p, http_req.header_len - (p - http_req.header) + 1);
                        http_req.header_len += first_len - (p - http_req.header);
                        free(http_req.header);
                        http_req.header = new_header;
                    }
                    memcpy(http_req.header, first, first_len);
                    free(first);
                }
                http_req.header[http_req.header_len] = '\0';
            break;

                default:
                    src_len = mod->src_len;
                    dest_len = mod->dest_len;
                    copy_new_mem(mod->src, src_len, &src);
                    copy_new_mem(mod->dest, dest_len, &dest);
                    src = keywords_replace(src, &src_len, client->reqType, &http_req);
                    dest = keywords_replace(dest, &dest_len, client->reqType, &http_req);
                    if (mod->flag == STRREP)
                        http_req.header = replace(http_req.header, &http_req.header_len, src, src_len, dest, dest_len);
                    else  //正则替换
                        http_req.header = regrep(http_req.header, &http_req.header_len, src, dest, dest_len);
                    free(src);
                    free(dest);
                    if (http_req.header == NULL)
                        goto error;
                break;
        }
        mod = mod->next;
    }

    /* 连接修改后的请求头和其他数据 */
    if (client->ready_data)
    {
        p = (char *)realloc(client->ready_data, client->ready_data_len + http_req.header_len);
        if (p == NULL)
            goto error;
        memcpy(p + client->ready_data_len, http_req.header, http_req.header_len);
        client->ready_data = p;
        client->ready_data_len += http_req.header_len;
    }
    else
    {
        client->ready_data = http_req.header;
        client->ready_data_len = http_req.header_len;
        http_req.header = NULL;
    }
    if (http_req.other)
    {
        //严格模式，修改所有请求头
        if (global.strict_modify)
        {
            int8_t type = client->reqType;
            client->reqType = request_type(http_req.other);
            if (modify_request(http_req.other, http_req.other_len, client) != 0)
            {
                http_req.other = NULL;
                goto error;
            }
            http_req.other = NULL;
            client->reqType = type;
        }
        else
        {
            p = (char *)realloc(client->ready_data, client->ready_data_len + http_req.other_len);
            if (p == NULL)
                goto error;
            client->ready_data = p;
            memcpy(p + client->ready_data_len, http_req.other, http_req.other_len);
            client->ready_data_len += http_req.other_len;
        }
    }

    //检测状态uri
    if (http_req.uri && strcmp(http_req.uri, "/cp") == 0)
    {
        rsp_stats_msg(client, http_req.host);
        free_http_request(&http_req);
        return 1;
    }
    //记录Host，之后构建CONNECT请求可能需要
    if ((client+1)->fd < 0)
    {
        client->host = http_req.host;
        http_req.host = NULL;
    }
    free_http_request(&http_req);
    return 0;

    error:
    free_http_request(&http_req);
    return -1;
}

