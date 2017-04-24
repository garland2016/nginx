
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t                         max_cached;  //最大缓存连接个数，由keepalive参数指定

    /*长连接队列，其中cache为缓存连接池，free为空闲连接池。初始化时根据keepalive
    指令的参数初始化free队列，后续有连接过来从free队列
    取连接，请求处理结束后将长连接缓存到cache队列，连接被断开（或超时）再从cache
    队列放入free队列*/
    ngx_queue_t                        cache;       //缓存的连接队列
    ngx_queue_t                        free;        //空闲的连接队列

    ngx_http_upstream_init_pt          original_init_upstream;
    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_upstream_keepalive_srv_conf_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    //缓存连接池中保存的后端服务器的地址，后续就是根据相同的socket地址来找出
    //对应的连接，并使用该连接
    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

} ngx_http_upstream_keepalive_cache_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    /*保存原始获取peer和释放peer的钩子，
    它们通常是ngx_http_upstream_get_round_robin_peer和ngx_http_upstream_free_round_robin_peer，
    nginx负载均衡默认是使用轮询算法*/
    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

} ngx_http_upstream_keepalive_peer_data_t;


static ngx_int_t ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void *ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_keepalive_commands[] = {

    { ngx_string("keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,     //NGX_HTTP_UPS_CONF 表示该指令的适用范围是upstream{}
      ngx_http_upstream_keepalive,          //负载均衡模块的钩子函数
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_keepalive_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_keepalive_module_ctx, /* module context */
    ngx_http_upstream_keepalive_commands,    /* module directives */
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
ngx_http_upstream_init_keepalive(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                               i;
    ngx_http_upstream_keepalive_srv_conf_t  *kcf;
    ngx_http_upstream_keepalive_cache_t     *cached;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init keepalive");

    kcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_keepalive_module);

    // 先执行原始初始化upstream函数（即ngx_http_upstream_init_round_robin），该函数
    // 会根据配置的后端地址解析成socket地址，用于连接后端。并设置us->peer.init钩子
    // 为ngx_http_upstream_init_round_robin_peer
    if (kcf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    // 保存原钩子，并用keepalive的钩子覆盖旧钩子，初始化后端请求的时候会调用这个新钩子
    kcf->original_init_peer = us->peer.init;

    us->peer.init = ngx_http_upstream_init_keepalive_peer;

    /* allocate cache items and add to free queue */
    // 申请缓存项，并添加到free队列中，后续用从free队列里面取
    cached = ngx_pcalloc(cf->pool,
                sizeof(ngx_http_upstream_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&kcf->cache);
    ngx_queue_init(&kcf->free);

    for (i = 0; i < kcf->max_cached; i++) {
        ngx_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_keepalive_module);

    kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    if (kcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_upstream_get_keepalive_peer;   //获取对端的钩子
    r->upstream->peer.free = ngx_http_upstream_free_keepalive_peer; //释放对端的钩子

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_keepalive_save_session;
#endif

    return NGX_OK;
}

//从cache池内获取对端服务器的连接
static ngx_int_t
ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_int_t          rc;
    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;   //缓存的连接队列

    //遍历整个cache的连接池队列
    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        //根据Socket IP地址来比较
        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->conf->free, q);  //放到free空闲队列中去

            goto found;
        }
    }

    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    c->idle = 0;
    c->sent = 0;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}


static void
ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (!u->request_body_sent) {
        goto invalid;
    }

    if (ngx_terminate || ngx_exiting) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (ngx_queue_empty(&kp->conf->free)) { //如果free空闲队列是空的

        q = ngx_queue_last(&kp->conf->cache);   //从缓存的队列中取最后一个
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

        //关闭这个连接
        ngx_http_upstream_keepalive_close(item->connection);

    } 
    else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
    }

    //放到缓存的队列中去
    ngx_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;

    pc->connection = NULL;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
    c->read->handler = ngx_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        ngx_http_upstream_keepalive_close_handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;
    ngx_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    ngx_http_upstream_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
}


static void
ngx_http_upstream_keepalive_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void *
ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->max_cached = 0;
     */

    return conf;
}


static char *
ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t            *uscf;
    ngx_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    ngx_int_t    n;
    ngx_str_t   *value;

    if (kcf->max_cached) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR || n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    // 设置指令配置的最大缓存连接数
    kcf->max_cached = n;

    // 获取upstream模块的server conf
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    // 保存原来的初始化upstream的钩子，并设置新的钩子
    kcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_http_upstream_init_round_robin;

    //设置init_upstream回调
    uscf->peer.init_upstream = ngx_http_upstream_init_keepalive;

    return NGX_CONF_OK;
}
