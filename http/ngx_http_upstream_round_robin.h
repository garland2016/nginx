
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

//nginx 对于后端的服务器可以采用两种分流策略：加权分流和ip hash
//ngx_http_upstream_round_robin模块主要负责 加权分流的功能
//对于权重较高的机器，被选中的概率大，对于权重相同的机器，则采用轮询方式

typedef struct ngx_http_upstream_rr_peer_s   ngx_http_upstream_rr_peer_t;

//后台服务器的具体信息
struct ngx_http_upstream_rr_peer_s {
    //基本socket信息
    struct sockaddr                *sockaddr;       
    socklen_t                       socklen;
    ngx_str_t                       name;
    ngx_str_t                       server;

    //当前权重值和设定权重值
    ngx_int_t                       current_weight;
    ngx_int_t                       effective_weight;
    ngx_int_t                       weight;

    ngx_uint_t                      conns;
    ngx_uint_t                      max_conns;

    //失败次数和访问时间
    ngx_uint_t                      fails;
    time_t                          accessed;
    time_t                          checked;

    //失败次数上限值和失败时间阈值
    ngx_uint_t                      max_fails;
    time_t                          fail_timeout;
    ngx_msec_t                      slow_start;
    ngx_msec_t                      start_time;

    //服务器是否参与策略,是否被置为down
    ngx_uint_t                      down;

    //ssl相关
#if (NGX_HTTP_SSL || NGX_COMPAT)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_atomic_t                    lock;
#endif

    ngx_http_upstream_rr_peer_t    *next;

    NGX_COMPAT_BEGIN(32)
    NGX_COMPAT_END
};


typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;

//round robin后端服务器信息
struct ngx_http_upstream_rr_peers_s {
    ngx_uint_t                      number;         //该群组后端服务器数量

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_slab_pool_t                *shpool;
    ngx_atomic_t                    rwlock;
    ngx_http_upstream_rr_peers_t   *zone_next;
#endif

    ngx_uint_t                      total_weight;

    unsigned                        single:1;       //该群组是否只有一台服务器
    unsigned                        weighted:1;

    ngx_str_t                      *name;

    ngx_http_upstream_rr_peers_t   *next;   //下个upstream节点,即下一个服务器群的指针

    ngx_http_upstream_rr_peer_t    *peer;   //服务器群中的第一个服务器，如果还有其它的服务器
};


#if (NGX_HTTP_UPSTREAM_ZONE)

#define ngx_http_upstream_rr_peers_rlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_rlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_wlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_unlock(peers)                              \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peers->rwlock);                                    \
    }


#define ngx_http_upstream_rr_peer_lock(peers, peer)                           \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }

#define ngx_http_upstream_rr_peer_unlock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define ngx_http_upstream_rr_peers_rlock(peers)
#define ngx_http_upstream_rr_peers_wlock(peers)
#define ngx_http_upstream_rr_peers_unlock(peers)
#define ngx_http_upstream_rr_peer_lock(peers, peer)
#define ngx_http_upstream_rr_peer_unlock(peers, peer)

#endif


typedef struct {
    ngx_uint_t                      config;
    ngx_http_upstream_rr_peers_t   *peers;      //所有服务器群的指针
    ngx_http_upstream_rr_peer_t    *current;    //current是当前尝试到哪台服务器。
    uintptr_t                      *tried;      //服务器位图指针，用于记录服务器当前的状态
    //tried字段实现了一个位图。对于后端服务器小于32台时，使用一个32位int来标识各个服务器是否尝试连接过。
    //当后端服务器大于32台时，会在内存池中新申请内存来存储该位图。
    uintptr_t                       data;       //data是该字段实际存储的位置。
} ngx_http_upstream_rr_peer_data_t;


ngx_int_t ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif


#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
