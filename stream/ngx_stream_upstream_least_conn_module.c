
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static ngx_int_t ngx_stream_upstream_init_least_conn_peer(
    ngx_stream_session_t *s, ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_least_conn_peer(
    ngx_peer_connection_t *pc, void *data);
static char *ngx_stream_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_upstream_least_conn_commands[] = {

    { ngx_string("least_conn"),
      NGX_STREAM_UPS_CONF|NGX_CONF_NOARGS,  //NGX_HTTP_UPS_CONF 表示该指令的适用范围是upstream{}
      ngx_stream_upstream_least_conn,       //钩子函数
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_least_conn_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL                                     /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_least_conn_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_least_conn_module_ctx, /* module context */
    ngx_stream_upstream_least_conn_commands, /* module directives */
    NGX_STREAM_MODULE,                       /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_upstream_init_least_conn(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0,
                   "init least conn");

    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_stream_upstream_init_least_conn_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_least_conn_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init least conn peer");

    if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    s->upstream->peer.get = ngx_stream_upstream_get_least_conn_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_least_conn_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t *rrp = data;

    time_t                           now;
    uintptr_t                        m;
    ngx_int_t                        rc, total;
    ngx_uint_t                       i, n, p, many;
    ngx_stream_upstream_rr_peer_t   *peer, *best;
    ngx_stream_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return ngx_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->connection = NULL;

    now = ngx_time();

    peers = rrp->peers;

    ngx_stream_upstream_rr_peers_wlock(peers);

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        /*
         * select peer with least number of connections; if there are
         * multiple peers with the same number of connections, select
         * based on round-robin
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

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, many");

        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }

            if (peer->down) {
                continue;
            }

            if (peer->conns * best->weight != best->conns * peer->weight) {
                continue;
            }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_stream_upstream_rr_peers_unlock(peers);

        rc = ngx_stream_upstream_get_least_conn_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        ngx_stream_upstream_rr_peers_wlock(peers);
    }

    ngx_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NGX_BUSY;
}


static char *
ngx_stream_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    //printf("ngx_stream_upstream_least_conn!\r\n");
    ngx_stream_upstream_srv_conf_t  *uscf;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    //设置init_upstream回调
    uscf->peer.init_upstream = ngx_stream_upstream_init_least_conn;

    //设置flags
    uscf->flags = NGX_STREAM_UPSTREAM_CREATE        //创建标志，如果含有创建标志的话，nginx会检查重复创建，以及必要参数是否填写
                  |NGX_STREAM_UPSTREAM_WEIGHT       //可以在server中使用weight属性
                  |NGX_STREAM_UPSTREAM_MAX_CONNS    //可以在server中使用max_conns属性
                  |NGX_STREAM_UPSTREAM_MAX_FAILS    //可以在server中使用max_fails属性
                  |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT //可以在server中使用fail_timeout属性
                  |NGX_STREAM_UPSTREAM_DOWN         //可以在server中使用down属性
                  |NGX_STREAM_UPSTREAM_BACKUP;      //可以在server中使用backup属性

    return NGX_CONF_OK;
}
