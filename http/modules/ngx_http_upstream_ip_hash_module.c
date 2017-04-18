
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;

    ngx_uint_t                         hash;

    u_char                             addrlen;
    u_char                            *addr;

    u_char                             tries;

    ngx_event_get_peer_pt              get_rr_peer;
} ngx_http_upstream_ip_hash_peer_data_t;


static ngx_int_t ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_ip_hash_commands[] = {

    { ngx_string("ip_hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,        //NGX_HTTP_UPS_CONF 表示该指令的适用范围是upstream{}
      ngx_http_upstream_ip_hash,                //钩子函数
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_ip_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ip_hash_module_ctx, /* module context */
    ngx_http_upstream_ip_hash_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char ngx_http_upstream_ip_hash_pseudo_addr[3];


static ngx_int_t
ngx_http_upstream_init_ip_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    //IP hash模块首先调用另一个负载均衡模块Round Robin的初始化函数
    //这是因为IP hash模块在某server掉线以后会使用RR模块的算法计算备用server
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    //再设置自己的处理请求阶段初始化钩子
    us->peer.init = ngx_http_upstream_init_ip_hash_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    struct sockaddr_in                     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    ngx_http_upstream_ip_hash_peer_data_t  *iphp;

    //建立保存服务器集群的表格
    iphp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return NGX_ERROR;
    }

    //设置数据指针，这个指针就是指向前面提到的那张表
    r->upstream->peer.data = &iphp->rrp;

    //调用Round Robin模块的回调函数对该模块进行请求初始化,
    //ngx_http_upstream_init_round_robin_peer 是Round Robin模块的处理请求阶段初始化的钩子函数
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    //设置一个新的回调函数get,该函数负责从表中取出某个服务器
    r->upstream->peer.get = ngx_http_upstream_get_ip_hash_peer;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = ngx_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer; //默认用round_robin加权轮询算法

    return NGX_OK;
}

/*用于从集群中选取一台后端服务器
从集群中选出一台后端来处理本次请求
选定后端的地址保存在pc->sockaddr，pc为主动连接。
NGX_DONE：选定一个后端，和该后端的连接已经建立。之后会直接发送请求。
NGX_OK：选定一个后端，和该后端的连接尚未建立。之后会和后端建立连接。
NGX_BUSY：所有的后端（包括备份集群）都不可用。之后会给客户端发送502（Bad Gateway）*/
static ngx_int_t
ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ip_hash_peer_data_t  *iphp = data;

    time_t                        now;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    i, n, p, hash;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    ngx_http_upstream_rr_peers_wlock(iphp->rrp.peers);

    //如果表格中只有一台服务器或已经尝试了大于20次
    if (iphp->tries > 20 || iphp->rrp.peers->single) {
        ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);   //用round robin轮询加权算法
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = iphp->hash;

    /* 遍历后端集群 */
    for ( ;; ) {

        for (i = 0; i < (ngx_uint_t) iphp->addrlen; i++) {
            hash = (hash * 113 + iphp->addr[i]) % 6271;
        }

        w = hash % iphp->rrp.peers->total_weight;
        peer = iphp->rrp.peers->peer;
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        /* 检查此后端在状态位图中对应的位，为1时表示不可用 */ 
        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (iphp->rrp.tried[n] & m) {
            goto next;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);

        /* 如果此后端指令中携带了down属性，表明此后端永久不可用 */
        if (peer->down) {
            goto next;
        }

        /* 如果此后端服务器的失败次数，超过了允许的最大值，那么不允许使用此后端了 */ 
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            goto next;
        }

        /* 如果此后端服务器的最大连接数已经超过了允许的最大值，则不允许使用此后端了 */
        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto next;
        }

        break;

    next:

        if (++iphp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
            return iphp->get_rr_peer(pc, &iphp->rrp);
        }
    }

    iphp->rrp.current = peer;

    /* 保存选定的后端服务器的地址，之后会向这个地址发起连接 */ 
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    /* 增加选定后端的当前连接数 */  
    peer->conns++;

    /* 更新checked时间 */
    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);

    /* 对于此请求，如果之后需要再次选取后端，不能再选取这个后端了 */
    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;

    return NGX_OK;
}

//负载均衡模块的钩子代码的规律是:一是uscf->flags的设置，另一个是设置init_upstream回调
static char *
ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    //printf("ngx_http_upstream_ip_hash!\r\n");
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    //init_upstream回调的设置
    uscf->peer.init_upstream = ngx_http_upstream_init_ip_hash;

    //uscf->flags的设置
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE          //创建标志，如果含有创建标志的话，nginx会检查重复创建，以及必要参数是否填写
                  |NGX_HTTP_UPSTREAM_WEIGHT         //可以在server中使用weight属性
                  |NGX_HTTP_UPSTREAM_MAX_CONNS      //可以在server中使用max_conns属性
                  |NGX_HTTP_UPSTREAM_MAX_FAILS      //可以在server中使用max_fails属性
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT   //可以在server中使用fail_timeout属性
                  |NGX_HTTP_UPSTREAM_DOWN;          //可以在server中使用down属性

    return NGX_CONF_OK;
}
