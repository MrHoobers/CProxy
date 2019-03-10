#include "conf.h"

/* HTTPS模式的字符串提前修改 */
static char *ssl_req_replace(char *str, int *len)
{
    str = replace(str, len, "[M]", 3, "CONNECT", 7);
    str = replace(str, len, "[V]", 3, "HTTP/1.1", 8);
    str = replace(str, len, "[U]", 3, "/", 1);
    return replace(str, len, "[url]", 5, "[H]", 3);
}

/* 字符串预处理，设置转义字符 */
static void string_pretreatment(char *str, int *len) {
    char *lf,
        *p,
        *ori_strs[] = {"\\r", "\\n", "\\b", "\\v", "\\f", "\\t", "\\a", "\\b", "\\0"},
        to_chrs[] = {'\r', '\n', '\b', '\v', '\f', '\t', '\a', '\b', '\0'};
    int i;

    while ((lf = strchr(str, '\n')) != NULL)
    {
        for (p = lf + 1; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; p++)
            *len -= 1;
        strcpy(lf, p);
        *len -= 1;
    }
    for (i = 0; i < sizeof(to_chrs); i++) {
        for (p = strstr(str, ori_strs[i]); p; p = strstr(p, ori_strs[i])) {
            //支持\\r
            *(p-1) == '\\' ? (*p--) : (*p = to_chrs[i]);
            memmove(p+1, p+2, strlen(p+2));
            (*len)--;
        }
    }
}


/* 在content中，设置变量(var)的首地址，值(val)的位置首地址和末地址，返回下一行指针 */
static char *set_var_val_lineEnd(char *content, char **var, char **val_begin, char **val_end)
{
    char *p, *pn, *lineEnd;
    ;
    int val_len;

    while (1)
    {
        if (content == NULL)
            return NULL;

        for (;*content == ' ' || *content == '\t' || *content == '\r' || *content == '\n'; content++);
        if (*content == '\0')
            return NULL;
        *var = content;
        pn = strchr(content, '\n');
        p = strchr(content, '=');
        if (p == NULL)
        {
            if (pn)
            {
                content = pn + 1;
                continue;
            }
            else
                return NULL;
        }
        content = p;
        //将变量以\0结束
        for (p--; *p == ' ' || *p == '\t'; p--);
        *(p+1) = '\0';
        //值的首地址
        for (content++; *content == ' ' || *content == '\t'; content++);
        if (*content == '\0')
            return NULL;
        //双引号引起来的值支持换行
        if (*content == '"')
        {
            *val_begin = content + 1;
            *val_end = strstr(*val_begin, "\";");
            if (*val_end != NULL)
                break;
        }
        else
            *val_begin = content;
        *val_end = strchr(content, ';');
        if (pn && *val_end > pn)
        {
            content = pn + 1;
            continue;
        }
        break;
    }

    if (*val_end)
    {
        **val_end = '\0';
        val_len = *val_end - *val_begin;
        lineEnd = *val_end;
    }
    else
    {
        val_len = strlen(*val_begin);
        *val_end = lineEnd = *val_begin + val_len;
    }
    string_pretreatment(*val_begin, &val_len);
    *val_end = *val_begin + val_len;
    //printf("var[%s]\nbegin[%s]\n\n", *var, *val_begin);
    return lineEnd;
}

/* 在buff中读取模块(global http https httpdns httpudp)内容 */
static char *read_module(char *buff, const char *module_name)
{
    int len;
    char *p, *p0;

    len = strlen(module_name);
    p = buff;
    while (1)
    {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (strncasecmp(p, module_name, len) == 0)
        {
            p += len;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
                p++;
            if (*p == '{')
                break;
        }
        if ((p = strchr(p, '\n')) == NULL)
            return NULL;
    }
    if ((p0 = strchr(++p, '}')) == NULL)
        return NULL;

    //printf("%s\n%s", module_name, content);
    return strndup(p, p0 - p);
}

static void parse_global_module(char *content)
{
    char *var, *val_begin, *val_end, *lineEnd, *p;

    while ((lineEnd = set_var_val_lineEnd(content, &var, &val_begin, &val_end)) != NULL)
    {
        if (strcasecmp(var, "mode") == 0)
        {
            if (strcasecmp(val_begin, "wap_connect") == 0)
                global.mode = WAP_CONNECT;
           else  if (strcasecmp(val_begin, "wap") == 0)
                global.mode = WAP;
           else  if (strcasecmp(val_begin, "net_connect") == 0)
                global.mode = NET_CONNECT;
           else  if (strcasecmp(val_begin, "net_proxy") == 0)
                global.mode = NET_PROXY;
        }
        else if (strcasecmp(var, "uid") == 0)
        {
            global.uid = atoi(val_begin);
        }
        else if (strcasecmp(var, "procs") == 0)
        {
            global.procs = atol(val_begin);
        }
        else if (strcasecmp(var, "tcp_listen") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                global.tcp_listen_fd = tcp_listen(val_begin, atoi(p + 1));
            }
            else
                global.tcp_listen_fd = tcp_listen((char *)"0.0.0.0", atoi(val_begin));
        }
        else if (strcasecmp(var, "dns_listen") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                global.dns_listen_fd = udp_listen(val_begin, atoi(p+1));
            }
            else
                global.dns_listen_fd = udp_listen((char *)"127.0.0.1", atoi(val_begin));
        }
        else if (strcasecmp(var, "udp_listen") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                global.udp_listen_fd = udp_listen(val_begin, atoi(p+1));
            }
            else
                global.udp_listen_fd = udp_listen((char *)"0.0.0.0", atoi(val_begin));
        }
        else if (strcasecmp(var, "strict") == 0 && strcasecmp(val_begin, "on") == 0)
        {
            global.strict_modify = 1;
        }
        else if (strcasecmp(var, "timeout") == 0)
        {
            global.timeout_m = atoi(val_begin);
        }

        content = strchr(lineEnd+1, '\n');
    }
}

/* 读取TCP模块 */
static int8_t parse_tcp_module(char *content, struct tcp_mode *tcp,int8_t https)
{
    struct modify *m, *m_save;
    struct ssl_string *s;
    char *var, *val_begin, *val_end, *lineEnd, *p, *str1_end, *str2_begin;

    m = NULL;
    s = ssl_str;
    while((lineEnd = set_var_val_lineEnd(content, &var, &val_begin, &val_end)) != NULL)
    {
        if (strcasecmp(var, "addr") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                tcp->dst.sin_addr.s_addr = inet_addr(val_begin);
                tcp->dst.sin_port = htons(atoi(p + 1));
            }
            else
            {
                tcp->dst.sin_addr.s_addr = inet_addr(val_begin);
                tcp->dst.sin_port = htons(80);
            }
            goto next_line;
        }

        /* 以下判断为链表操作 */
        m_save = m; //保存前一个结构体指针
        if (m)
            m = m->next = (struct modify *)malloc(sizeof(*m));
        else
           tcp->m = m = (struct modify *)malloc(sizeof(*m));
        if (m == NULL)
            return 1;
        memset((struct modify *)m, 0, sizeof(*m));
        if (strcasecmp(var, "del_hdr") == 0)
        {
            m->flag = DEL_HDR;
            m->del_hdr = strdup(val_begin);
            m->del_hdr_len = strlen(m->del_hdr);
            if (m->del_hdr == NULL)
                return 1;
        }
        else if (strcasecmp(var, "set_first") == 0)
        {
            m->first_len = val_end - val_begin;
            copy_new_mem(val_begin, m->first_len, &m->first);
            //https模块首先替换部分字符串
            if (https)
                m->first = ssl_req_replace(m->first, &m->first_len);
            if (m->first == NULL)
                return 1;
            m->flag = SET_FIRST;
        }
        else if (strcasecmp(var, "strrep") == 0 || strcasecmp(var, "regrep") == 0 || strcasecmp(var, "save_hdr") == 0)
        {
            //定位 [源字符串结束地址] 和 [目标字符串首地址]
            p = strstr(val_begin, "->");
            if (p == NULL)
                return 1;
            for (str1_end = p - 1; *str1_end == ' '; str1_end--)
            {
                if (str1_end == val_begin)
                    return 1;
            }
            if (*str1_end == '"')
                str1_end--;
            for (str2_begin = p + 2; *str2_begin == ' '; str2_begin++)
            {
                if (str2_begin == val_end)
                    return 1;
            }
            if (*str2_begin == '"')
                str2_begin++;
            /* 保存头域 */
            if (var[1] == 'a')
            {
                m->saveHdr = (struct save_header *)calloc(1, sizeof(struct save_header));
                if (m->saveHdr == NULL)
                    return 1;
                m->saveHdr->next = saveHdrs;
                saveHdrs = m->saveHdr;
                saveHdrs->key = strndup(val_begin, str1_end - val_begin + 1);
                if (saveHdrs->key == NULL)
                    return 1;
                saveHdrs->key_len = strlen(saveHdrs->key);
                saveHdrs->replace_string_len = saveHdrs->key_len + 9;
                saveHdrs->replace_string = (char *)malloc(saveHdrs->replace_string_len + 1);
                if (saveHdrs->replace_string == NULL)
                    return 1;
                sprintf(saveHdrs->replace_string, "use_hdr(%s)", saveHdrs->key);
                saveHdrs->updateTime = atoi(str2_begin);
                m->flag = SAVE_HDR;
            }
            else
            {                
                m->src_len = str1_end - val_begin;
                m->dest_len = val_end - str2_begin;
                copy_new_mem(val_begin, m->src_len, &m->src);
                if (m->dest_len)
                    copy_new_mem(str2_begin, m->dest_len, &m->dest);
                else
                    m->dest = (char *)calloc(1, 1);
                if (https)
                {
                    m->src = ssl_req_replace(m->src, &m->src_len);
                    m->dest = ssl_req_replace(m->dest, &m->dest_len);
                }
                if (m->src == NULL || m->dest == NULL)
                    return 1;
                if (*var == 's')  //如果是普通字符串替换
                    m->flag = STRREP;
                else  //正则表达式字符串替换
                {
                    //正则表达式中\b与c语言中的\b不一样
                    replace(m->src, &m->src_len, "\\\b", 2, "\\b", 2);
                    replace(m->dest, &m->dest_len, "\\\b", 2, "\\b", 2);
                    m->flag = REGREP;
                }
            }
        }
        else if (https == 0)
        {
            if (strcasecmp(var, "uri_strict") == 0 && strcasecmp(val_begin, "on") == 0)
            {
                tcp->uri_strict = 1;
            }
            else if (strcasecmp(var, "only_get_post") == 0 && strcasecmp(val_begin, "on") == 0)
            {
                tcp->http_only_get_post = 1;
            }
            else if (strcasecmp(var, "proxy_https_string") == 0)
            {
                s = (struct ssl_string *)malloc(sizeof(*s));
                if (s == NULL)
                    return 1;
                s->str = strdup(val_begin);
                if (s->str == NULL)
                    return 1;
                s->next = ssl_str;
                ssl_str = s;
            }
        }
        else if (strncasecmp(var, "encode", 6) == 0)
        {
            tcp->encodeCode = (unsigned)atoi(val_begin);
        }
        if (m->flag == 0)
        {
            free(m);
            if (m_save)
            {
                m = m_save;
                m->next = NULL;
            }
            else
                tcp->m = m = NULL;
        }

        next_line:
        content = strchr(lineEnd+1, '\n');
    }

    return 0;
}

/* 读取HTTPDNS模块 */
static int8_t parse_httpdns_module(char *content)
{
    char *var, *val_begin, *val_end, *lineEnd, *p;

    while ((lineEnd = set_var_val_lineEnd(content, &var, &val_begin, &val_end)) != NULL)
    {
        if (strcasecmp(var, "addr") == 0)
        {
            if ( (p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                httpdns.dst.sin_port = htons(atoi(p+1));
            }
            else
            {
                httpdns.dst.sin_port = htons(80);
            }
            httpdns.dst.sin_addr.s_addr = inet_addr(val_begin);
        }
        else if(strcasecmp(var, "mode") == 0 && strcasecmp(val_begin, "tcpDNS") == 0)
        {
            httpdns.tcpDNS_mode = 1;
        }
        else if(strcasecmp(var, "http_req") == 0)
        {
            httpdns.http_req_len = val_end - val_begin;
            if (copy_new_mem(val_begin, httpdns.http_req_len, &httpdns.http_req) != 0)
                return 1;
        }
        else if (strcasecmp(var, "cachePath") == 0)
        {
            httpdns.cachePath = strdup(val_begin);
            if (httpdns.cachePath == NULL || read_cache_file() != 0)
                return 1;
        }
        else if (strcasecmp(var, "cacheLimit") == 0)
        {
            httpdns.cacheLimit = atoi(val_begin);
        }
        else if (strcasecmp(var, "encode") == 0)
        {
            httpdns.encodeCode = (unsigned)atoi(val_begin);
        }

        content = strchr(lineEnd+1, '\n');
    }

    return 0;
}

static int8_t parse_httpudp_module(char *content)
{
    char *var, *val_begin, *val_end, *lineEnd, *p;
    while ((lineEnd = set_var_val_lineEnd(content, &var, &val_begin, &val_end)) != NULL)
    {
        if (strcasecmp(var, "addr") == 0)
        {
            if ( (p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                udp.dst.sin_port = htons(atoi(p+1));
            }
            else
            {
                udp.dst.sin_port = htons(80);
            }
            udp.dst.sin_addr.s_addr = inet_addr(val_begin);
        }
        else if (strcasecmp(var, "http_req") == 0)
        {
            udp.http_request_len = val_end - val_begin;
            if (copy_new_mem(val_begin, udp.http_request_len, &udp.http_request) != 0)
                return 1;
        }
        else if (strcasecmp(var, "encode") == 0)
        {
            udp.encodeCode = (unsigned)atoi(val_begin);
        }

        content = strchr(lineEnd+1, '\n');
    }

    return 0;
}

void read_conf(char *path)
{
    char *buff, *global_content, *http_content, *https_content, *httpdns_content, *httpudp_content;
    FILE *file;
    long file_size;

    /* 读取配置文件到缓冲区 */
    file = fopen(path, "r");
    if (file == NULL)
        error("cannot open config file.");
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    buff = (char *)alloca(file_size + 1);
    if (buff == NULL)
        error("out of memory.");
    rewind(file);
    fread(buff, file_size, 1, file);
    fclose(file);
    buff[file_size] = '\0';
    /* 读取global模块内容 */
    if ((global_content = read_module(buff, "global")) == NULL)
            error("read global module error");
    parse_global_module(global_content);
    free(global_content);
    /* 读取http https模块内容 */
    if (global.tcp_listen_fd >= 0)
    {
        if ((http_content = read_module(buff, "http")) == NULL || parse_tcp_module(http_content, &http, 0) != 0)
            error("read http module error");
        free(http_content);
        if ((https_content = read_module(buff, "https")) == NULL || parse_tcp_module(https_content, &https, 1) != 0)
            error("read https module error");
        free(https_content);
    }
    /* 读取httpdns模块 */
    if (global.dns_listen_fd >= 0)
    {
        if ((httpdns_content = read_module(buff, "httpdns")) == NULL || parse_httpdns_module(httpdns_content) != 0)
            error("read httpdns module error");
        free(httpdns_content);
    }
    /* 读取httpudp模块 */
    if (global.udp_listen_fd >= 0)
    {
        if ((httpudp_content = read_module(buff, "httpudp")) == NULL || parse_httpudp_module(httpudp_content) != 0)
            error("read httpudp module error");
        free(httpudp_content);
    }
}
