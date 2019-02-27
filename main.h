#ifndef MAIN_H
#define MAIN_H

#include "http_proxy.h"
#include "http_request.h"
#include "common.h"
#include "httpdns.h"
#include "httpudp.h"
#include "conf.h"

struct global {
    int tcp_listen_fd, dns_listen_fd, udp_listen_fd, uid, procs, timeout_m;
    unsigned mode :3,
        strict_modify :1;
};

extern struct global global;

#endif
