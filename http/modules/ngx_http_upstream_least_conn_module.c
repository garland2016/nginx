
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_least_conn_peer(
    ngx_peer_connection_t *pc, void *data);
static char *ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_least_conn_commands[] = {

    { ngx_string("least_conn"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,    //NGX_HTTP_UPS_CONF 表示该指令的适用范围是upstream{}
      ngx_http_upstream_least_conn,         //钩子函数
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_least_conn_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_least_conn_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_least_conn_module_ctx, /* module context */
    ngx_http_upstream_least_conn_commands, /* module directives */
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


static ngx_int_t
ngx_http_upstream_init_least_conn(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init least conn");

    //初始化round robin
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    //设置init
    us->peer.init = ngx_http_upstream_init_least_conn_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init least conn peer");

    //调用round robin的per request负载均衡初始化函数
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    //指定peer.get，用于从集群中选取一台后端服务器
    r->upstream->peer.get = ngx_http_upstream_get_least_conn_peer;

    return NGX_OK;
}

/*用于从集群中选取一台后端服务器
采用least connected算法，从集群中选出一台后端来处理本次请求
选定后端的地址保存在pc->sockaddr，pc为主动连接。
NGX_DONE：选定一个后端，和该后端的连接已经建立。之后会直接发送请求。
NGX_OK：选定一个后端，和该后端的连接尚未建立。之后会和后端建立连接。
NGX_BUSY：所有的后端（包括备份集群）都不可用。之后会给客户端发送502（Bad Gateway）*/
static ngx_int_t
ngx_http_upstream_get_least_conn_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;  /* 请求的负载均衡数据 */

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc, total;
    ngx_uint_t                     i, n, p, many;
    ngx_http_upstream_rr_peer_t   *peer, *best;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    /* 如果集群只包含一台后端，那么就不用选了 */ 
    if (rrp->peers->single) {
        return ngx_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = rrp->peers;     /* 所有后端集群 */

    ngx_http_upstream_rr_peers_wlock(peers);

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    /* 遍历后端集群 */
    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        /* 检查此后端在状态位图中对应的位，为1时表示不可用 */ 
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        /* 如果此后端指令中携带了down属性，表明此后端永久不可用 */
        if (peer->down) {
            continue;
        }

        /* 如果此后端服务器的失败次数，超过了允许的最大值，那么不允许使用此后端了 */ 
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        /* 如果此后端服务器的最大连接数已经超过了允许的最大值，则不允许使用此后端了 */
        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        /*
         * select peer with least number of connections; if there are
         * multiple peers with the same number of connections, select
         * based on round-robin
         */

        /* 比较各个后端的conns/weight，选取最小者； 
         * 如果有多个最小者，记录第一个的序号p，且设置many标志。 
         */  
        if (best == NULL
            || peer->conns * best->weight < best->conns * peer->weight)
        {
            best = peer;
            many = 0;
            p = i;

        } else if (peer->conns * best->weight == best->conns * peer->weight) {
            many = 1;
        }
    }

    /* 找不到可用的后端 */
    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    /* 如果有多个后端的conns/weight同为最小者，则对它们使用轮询算法 */ 
    if (many) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, many");

        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            /* 检查此后端在状态位图中对应的位，为1时表示不可用 */
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }

            /* 此后端指令中携带了down属性，表示后端永久不可用 */
            if (peer->down) {
                continue;
            }

            /* conns/weight必须为最小的 已经选定最小的是best了 */
            if (peer->conns * best->weight != best->conns * peer->weight) {
                continue;
            }

            /* 如果此后端服务器的失败次数，超过了允许的最大值，那么不允许使用此后端了 */
            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            /* 如果此后端服务器的最大连接数已经超过了允许的最大值，则不允许使用此后端了 */
            if (peer->max_conns && peer->conns >= peer->max_conns) {
                continue;
            }

            /* 对每个后端，增加其当前权重 */
            peer->current_weight += peer->effective_weight;

            /* 累加所有后端的有效权重 */
            total += peer->effective_weight;

            /* 如果之前此后端发生了失败，会减小其effective_weight来降低它的权重。           
             * 此后在选取后端的过程中，又通过增加其effective_weight来恢复它的权重。           
             */ 
            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            /* 选取当前权重最大者，作为本次选定的后端 */  
            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    /* 如果使用轮询，要降低选定后端的当前权重 */
    best->current_weight -= total;

    /* 更新checked时间 */
    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    /* 保存选定的后端服务器的地址，之后会向这个地址发起连接 */ 
    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    /* 增加选定后端的当前连接数 */  
    best->conns++;

    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    /* 对于此请求，如果之后需要再次选取后端，不能再选取这个后端了 */
    rrp->tried[n] |= m;

    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    /* 如果不能从集群中选取一台后端，那么尝试备用集群 */
    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_http_upstream_rr_peers_unlock(peers);

        /* 重新调用本函数 */
        rc = ngx_http_upstream_get_least_conn_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_http_upstream_rr_peers_wlock(peers);
    }

    ngx_http_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}


static char *
ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    //设置init_upstream回调
    uscf->peer.init_upstream = ngx_http_upstream_init_least_conn;

    //设置flagas
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE          //创建标志，如果含有创建标志的话，nginx会检查重复创建，以及必要参数是否填写
                  |NGX_HTTP_UPSTREAM_WEIGHT         //可以在server中使用weight属性
                  |NGX_HTTP_UPSTREAM_MAX_CONNS      //可以在server中使用max_conns属性
                  |NGX_HTTP_UPSTREAM_MAX_FAILS      //可以在server中使用max_fails属性
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT   //可以在server中使用fail_timeout属性
                  |NGX_HTTP_UPSTREAM_DOWN           //可以在server中使用down属性
                  |NGX_HTTP_UPSTREAM_BACKUP;        //可以在server中使用backup属性

    return NGX_CONF_OK;
}
