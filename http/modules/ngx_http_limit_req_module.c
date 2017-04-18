
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

//表示红黑树节点信息的数据结构
typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      len;           //变长 key 的长度
    ngx_queue_t                  queue;         //用来标识这个节点在LRU队列里的位置的，记录了上个节点和下一个节点
    ngx_msec_t                   last;          //上次更新时间
    /* integer value, 1 corresponds to 0.001 r/s */
    ngx_uint_t                   excess;        //表示上次处理完后剩下来的请求数 * 1000  (漏桶算法(Leaky Bucket))
    ngx_uint_t                   count;
    u_char                       data[1];
} ngx_http_limit_req_node_t;

//一个红黑树结点的内存大小为:
//size = offsetof(ngx_rbtree_node_t, color)
//     + offsetof(ngx_http_limit_req_node_t, data)
//     + key->len;

//共享内存结构体
typedef struct {
    ngx_rbtree_t                  rbtree;           //红黑树 记录每个 “域”（即根据 limit_req_zone 里定义的 key 得到）目前的状况
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;            //LRU 算法队列，按最近最久未使用 将红黑树节点按更新时间从早到晚串起来，用来淘汰过于陈旧的节点（LRU）
} ngx_http_limit_req_shctx_t;

//存放根据 limit_req_zone 指令创建的共享内存的相关上下文信息
typedef struct {
    ngx_http_limit_req_shctx_t  *sh;            //我们的共享数据结构
    ngx_slab_pool_t             *shpool;        //共享内存的slab分配
    /* integer value, 1 corresponds to 0.001 r/s */
    ngx_uint_t                   rate;          //根据指令 limit_req_zone 而解析得到
    ngx_http_complex_value_t     key;           //根据指令 limit_req_zone 而解析得到
    ngx_http_limit_req_node_t   *node;          //指向ngx_http_limit_req_node_t结点
} ngx_http_limit_req_ctx_t;

//存放了 limit_req 指令的相关配置信息
typedef struct {
    ngx_shm_zone_t              *shm_zone;  // 保存我们创建的共享内存,shm_zone->data 指向了ngx_http_limit_req_ctx_t
    /* integer value, 1 corresponds to 0.001 r/s */
    ngx_uint_t                   burst;             //表示一个 "域"（key）最多允许的突发请求数
    ngx_uint_t                   nodelay; /* unsigned  nodelay:1 */     //表示是否要延迟处理那些超出请求速率的请求
} ngx_http_limit_req_limit_t;

//存放配置项信息
typedef struct {
    ngx_array_t                  limits;        //保存ngx_http_limit_req_limit_t 的数组
    ngx_uint_t                   limit_log_level;
    ngx_uint_t                   delay_log_level;
    ngx_uint_t                   status_code;
} ngx_http_limit_req_conf_t;


static void ngx_http_limit_req_delay(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit,
    ngx_uint_t hash, ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account);
static ngx_msec_t ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits,
    ngx_uint_t n, ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit);
static void ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx,
    ngx_uint_t n);

static void *ngx_http_limit_req_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_req_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_limit_req_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_limit_req_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t  ngx_http_limit_req_commands[] = {

    { ngx_string("limit_req_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_limit_req_zone,          //读取配置文件时遇到limit_req_zone时调用，
      0,
      0,
      NULL },

    { ngx_string("limit_req"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_limit_req,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_req_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_conf_t, limit_log_level),
      &ngx_http_limit_req_log_levels },

    { ngx_string("limit_req_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_conf_t, status_code),
      &ngx_http_limit_req_status_bounds },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_req_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_limit_req_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_req_create_conf,        /* create location configuration */
    ngx_http_limit_req_merge_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_limit_req_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_req_module_ctx,        /* module context */
    ngx_http_limit_req_commands,           /* module directives */
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

//遍历设置好的共享内存，调用 ngx_http_limit_req_lookup 来判断是否需要进行禁用或者延迟，
//如果禁用，则返回设置的对应状态码；
//如果需要延迟，则将这条连接上的写事件处理方法设置为 ngx_http_limit_req_delay，
//并放入定时器中，过期时间通过 ngx_http_limit_req_account 计算出来
static ngx_int_t
ngx_http_limit_req_handler(ngx_http_request_t *r)
{
    uint32_t                     hash;
    ngx_str_t                    key;
    ngx_int_t                    rc;
    ngx_uint_t                   n, excess;
    ngx_msec_t                   delay;
    ngx_http_limit_req_ctx_t    *ctx;
    ngx_http_limit_req_conf_t   *lrcf;
    ngx_http_limit_req_limit_t  *limit, *limits;

    if (r->main->limit_req_set) {
        //如果这个请求的主请求已经进行了该阶段的检查
        //直接返回 NGX_DCLIEND，让下一个 HTTP 模块介入请求
        return NGX_DECLINED;
    }

    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_module);
    limits = lrcf->limits.elts;

    excess = 0;

    rc = NGX_DECLINED;

#if (NGX_SUPPRESS_WARN)
    limit = NULL;
#endif

    //遍历limits数组,遍历设置好的"域"
    for (n = 0; n < lrcf->limits.nelts; n++) {

        limit = &limits[n];

        ctx = limit->shm_zone->data;    //取出共享内存的数据

        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 65535) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        //计算 hash
        hash = ngx_crc32_short(key.data, key.len);

        ngx_shmtx_lock(&ctx->shpool->mutex);

        //在这个"域" 的红黑树上找这个 key 对应的节点
        rc = ngx_http_limit_req_lookup(limit, hash, &key, &excess,
                                       (n == lrcf->limits.nelts - 1));  //最后一个参数是标识着是否是最后一个域

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit_req[%ui]: %i %ui.%03ui",
                       n, rc, excess / 1000, excess % 1000);

        if (rc != NGX_AGAIN) {
            //只要 ngx_http_limit_req_lookup 返回的不是 NGX_AGAIN，就 break
            break;
        }
    }

    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    r->main->limit_req_set = 1; //设置这个请求的主请求已经进行了该阶段的检查

    if (rc == NGX_BUSY || rc == NGX_ERROR) {

        if (rc == NGX_BUSY) {
            ngx_log_error(lrcf->limit_log_level, r->connection->log, 0,
                          "limiting requests, excess: %ui.%03ui by zone \"%V\"",
                          excess / 1000, excess % 1000,
                          &limit->shm_zone->shm.name);
        }

        // 经历过的 n 个"域"，取出 node，将 count--
        while (n--) {
            ctx = limits[n].shm_zone->data;

            if (ctx->node == NULL) {
                continue;
            }

            ngx_shmtx_lock(&ctx->shpool->mutex);

            ctx->node->count--;

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            ctx->node = NULL;
        }

        return lrcf->status_code;
    }

    /* rc == NGX_AGAIN || rc == NGX_OK */

    if (rc == NGX_AGAIN) {
        excess = 0;
    }

    //计算好延迟时间
    delay = ngx_http_limit_req_account(limits, n, &excess, &limit);

    if (!delay) {
        return NGX_DECLINED;
    }

    ngx_log_error(lrcf->delay_log_level, r->connection->log, 0,
                  "delaying request, excess: %ui.%03ui, by zone \"%V\"",
                  excess / 1000, excess % 1000, &limit->shm_zone->shm.name);

    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        //这里处理下这条连接的读事件，是为了如果在这段延迟的时间内，客户端
        //主动关闭了连接，Nginx 也可以通过事件调度器感知到，从而及时断开连接
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_limit_req_delay;

    //添加到定时器红黑树上，等到过期时调用 ngx_http_limit_req_delay
    ngx_add_timer(r->connection->write, delay);

    /* 
     * 这里返回 NGX_AGAIN，让这个模块有机会再介入这个请求，
     * 其实也很好理解，毕竟 delay 之后，不能保证那个时刻这个请求涉及到的“域”
     * 就一定没有超过该“域” 的请求设置限制了，所以还需要再次计算
     */
    return NGX_AGAIN;
}

//作为写事件回调，再次运行 ngx_http_core_run_phases ，执行 HTTP 的 11 个阶段处理
static void
ngx_http_limit_req_delay(ngx_http_request_t *r)
{
    ngx_event_t  *wev;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "limit_req delay");

    wev = r->connection->write;

    if (!wev->timedout) {

        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    wev->timedout = 0;

    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;

    ngx_http_core_run_phases(r);
}


static void
ngx_http_limit_req_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_limit_req_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            /*
             * 值相等不见得 key 一定相同，存在 hash 冲突的
             * 前面说过，ngx_http_limit_req_node_t 和 ngx_rbtree_node_t 
             * 复用了 color 和 data 这两个字段，ngx_http_limit_req_node_t 的地址
             * 就是 ngx_rbtree_node_t 里的 color 字段的地址
             */
            lrn = (ngx_http_limit_req_node_t *) &node->color;
            lrnt = (ngx_http_limit_req_node_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;

    //新加入节点需要涂成红色
    ngx_rbt_red(node);
}

/*
这个函数是核心，在某个“域”的红黑树上找到对应 hash 值的节点，根据漏桶算法，以固定速率处理请求，
但又不仅仅是漏桶算法，这里还包含了令牌桶算法的突发门限，
具体表现在只要不超过突发门限值，就不会返回 NGX_BUSY，这样就可以处理一定量的突发请求了。
返回值的意义：
- NGX_BUSY 超过了突发门限
- NGX_OK 没有超过限制的请求频率
- NGX_AGAIN 超过限制的请求频率，但是没有到达突发门限
*/
static ngx_int_t
ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit, ngx_uint_t hash,
    ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account)
{
    size_t                      size;
    ngx_int_t                   rc, excess;
    ngx_msec_t                  now;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lr;

    now = ngx_current_msec;                 //取得当前的时间毫秒值

    ctx = limit->shm_zone->data;

    node = ctx->sh->rbtree.root;            //找到这个"域"对应的红黑树
    sentinel = ctx->sh->rbtree.sentinel;

    //遍历红黑树，根据hash值查找
    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lr = (ngx_http_limit_req_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);

        //hash值相同，且 key 相同，才算是找到
        if (rc == 0) {

            //这个节点最近才访问，放到队列首部，最不容易被淘汰（LRU 思想）
            ngx_queue_remove(&lr->queue);
            ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);


            /*
             * 漏桶算法：以固定速率接受请求，每秒接受 rate 个请求，
             * ms 是距离上次处理这个 key 到现在的时间，单位 ms
             * lr->excess 是上次还遗留着被延迟的请求数（*1000）
             * excess = lr->excess - ctx->rate * ngx_abs(ms) / 1000 + 1000;
             * 本次还会遗留的请求数就是上次遗留的减去这段时间可以处理掉的加上这个请求本身（之前 burst 和 rate 都放大了 1000 倍）
             */
            ms = (ngx_msec_int_t) (now - lr->last);

            excess = lr->excess - ctx->rate * ngx_abs(ms) / 1000 + 1000;

            if (excess < 0) {
                //全部处理完了
                excess = 0;
            }

            *ep = excess;

            if ((ngx_uint_t) excess > limit->burst) {
                //这段时间处理之后，遗留的请求数超出了突发请求限制
                return NGX_BUSY;
            }

            if (account) {
                /* 这个请求到了最后一个“域”的限制
                 * 更新上次遗留请求数和上次访问时间
                 * 返回 NGX_OK 表示没有达到请求限制的频率
                 */
                lr->excess = excess;
                lr->last = now;
                return NGX_OK;
            }

            lr->count++;

            //这一步是为了在 ngx_http_limit_req_account 里更新这些访问过的节点的信息 
            ctx->node = lr;

            //返回 NGX_AGAIN，会进行下一个“域”的检查 
            return NGX_AGAIN;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    //没有在红黑树上找到节点
    *ep = 0;

    /* 
     * 新建一个节点，需要的内存大小，包括了红黑树节点大小
     * ngx_http_limit_req_node_t 还有 key 的长度
     */
    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_limit_req_node_t, data)
           + key->len;

    //先进行 LRU 淘汰，传入 n=1，则最多淘汰 2 个节点
    ngx_http_limit_req_expire(ctx, 1);

    // 在共享内存中创建一个结点，由于调用 ngx_http_limit_req_lookup 之前已经上过锁，这里不用再上
    node = ngx_slab_alloc_locked(ctx->shpool, size);

    if (node == NULL) {
        //分配失败考虑再进行一次 LRU 淘汰，及时释放共享内存空间，这里 n = 0，最多淘汰 3 个节点
        ngx_http_limit_req_expire(ctx, 0);

        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return NGX_ERROR;
        }
    }

    //设置相关的信息
    node->key = hash;

    // 下面对该结点进行初始化操作
    lr = (ngx_http_limit_req_node_t *) &node->color;

    lr->len = (u_short) key->len;
    lr->excess = 0;

    //初始化key
    ngx_memcpy(lr->data, key->data, key->len);

    //加入到rbtree里面
    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    //加入到队列里
    ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

    if (account) {
        //同样地，如果这是最后一个“域”的检查，就更新 last 和 count，返回 NGX_OK
        lr->last = now;
        lr->count = 0;
        return NGX_OK;
    }

    //否则就令 count = 1，把节点放到 ctx 上
    lr->last = 0;
    lr->count = 1;

    ctx->node = lr;

    return NGX_AGAIN;
}

//负责对目前的这个请求计算一个延时时间
static ngx_msec_t
ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits, ngx_uint_t n,
    ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit)
{
    ngx_int_t                   excess;
    ngx_msec_t                  now, delay, max_delay;
    ngx_msec_int_t              ms;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lr;

    excess = *ep;

    if (excess == 0 || (*limit)->nodelay) {
        max_delay = 0;

    } else {
        ctx = (*limit)->shm_zone->data;
        max_delay = excess * 1000 / ctx->rate;
    }

    //反向遍历之前遍历过的"域"
    while (n--) {
        ctx = limits[n].shm_zone->data;
        lr = ctx->node; //为了更新结点信息

        if (lr == NULL) {
            continue;
        }

        ngx_shmtx_lock(&ctx->shpool->mutex);

        now = ngx_current_msec;
        ms = (ngx_msec_int_t) (now - lr->last);

        excess = lr->excess - ctx->rate * ngx_abs(ms) / 1000 + 1000;

        if (excess < 0) {
            excess = 0;
        }

        //更新信息
        lr->last = now;
        lr->excess = excess;
        lr->count--;

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;

        if (limits[n].nodelay) {
            continue;
        }

        delay = excess * 1000 / ctx->rate;

        if (delay > max_delay) {
            max_delay = delay;
            *ep = excess;
            *limit = &limits[n];
        }
    }

    return max_delay;
}

//从队列（ngx_http_limit_req_shctx_t->queue）尾部遍历，将过期的红黑树节点删除，及时释放共享内存空间
static void
ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx, ngx_uint_t n)
{
    ngx_int_t                   excess;
    ngx_msec_t                  now;
    ngx_queue_t                *q;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node;
    ngx_http_limit_req_node_t  *lr;

    now = ngx_current_msec;

    /*
     * n == 1 deletes one or two zero rate entries  最多淘汰两个
     * n == 0 deletes oldest entry by force         最多淘汰三个
     *        and one or two zero rate entries
     */

    while (n < 3) {

        //如果队列是空
        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }

        // 队列尾部的节点最近最久没有访问，最有可能被淘汰
        q = ngx_queue_last(&ctx->sh->queue);

        //取出这最后一项的数据结点
        lr = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);

        if (lr->count) {

            /*
             * There is not much sense in looking further,
             * because we bump nodes on the lookup stage.
             */

            return;
        }

        if (n++ != 0) {

            ms = (ngx_msec_int_t) (now - lr->last);
            ms = ngx_abs(ms);

            if (ms < 60000) {
                return;
            }

            excess = lr->excess - ctx->rate * ms / 1000;

            if (excess > 0) {
                return;
            }
        }

        ngx_queue_remove(q);

        // lr = (ngx_http_limit_req_node_t *) &node->color;   由ngx_rbtree_node_t结点，得到 ngx_http_limit_req_node_t结点

        node = (ngx_rbtree_node_t *)
                   ((u_char *) lr - offsetof(ngx_rbtree_node_t, color));    //由ngx_http_limit_req_node_t结点 得到 ngx_rbtree_node_t结点 

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);
    }
}

//共享内存的初始化函数  负责初始化放在共享内存中的上下文信息，包括红黑树的初始化，队列初始化，所以每个“域
static ngx_int_t
ngx_http_limit_req_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_req_ctx_t  *octx = data;

    size_t                     len;
    ngx_http_limit_req_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {

        //这个过程发生在 reload 的时候，如果对应共享内存的 key 没变，直接复用就行了
        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        // 由于octx是本地内存中分配的，也是在old_cycle中分配的，所以需要在新的ctx中重新初始化一下
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    // 下面是关于共享内存中数据结构的初始化
    // 将共享内存指针转换成slab分配池管理，并保存
    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    // 从 slab 池申请一块存放 ngx_http_limit_req_shctx_t 的内存
    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_req_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    //把刚分配好的内存地址 指向 ngx_slab_pool_t的data成员
    ctx->shpool->data = ctx->sh;

    //初始化这个"域"的红黑树和 LRU 队列
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_limit_req_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


static void *
ngx_http_limit_req_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_req_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->limit_log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_req_conf_t *prev = parent;
    ngx_http_limit_req_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              NGX_LOG_ERR);

    conf->delay_log_level = (conf->limit_log_level == NGX_LOG_INFO) ?
                                NGX_LOG_INFO : conf->limit_log_level + 1;

    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_SERVICE_UNAVAILABLE);

    return NGX_CONF_OK;
}

//对指令 limit_req_zone 指令进行解析
//例:limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;  
static char *
ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_int_t                          rate, scale;
    ngx_uint_t                         i;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_limit_req_ctx_t          *ctx;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    //只要解析到一条 limit_req_zone 指令，就会创建一个 ctx
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];      //$binary_remote_addr
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    rate = 1;
    scale = 1;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        // 这里主要是在解析 zone 的 name 和 size   例如：zone=one:10m
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);      //区域大小

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        // 这里主要是解析 rate，包括解析单位 r/s 和 r/m，计算对应的 scale    例如：rate=1r/s
        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (ngx_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (ngx_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = ngx_atoi(value[i].data + 5, len - 5);
            if (rate <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    //未指定zone= 的情况
    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    //实际使用的 rate 会被放大 1000 倍
    ctx->rate = rate * 1000 / scale;

    //创建一块共享内存 name size tag
    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_req_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    //设置共享内存的自定义初始化方法，设置好 ctx 的索引
    shm_zone->init = ngx_http_limit_req_init_zone;
    shm_zone->data = ctx;           //shm_zone->data 指向了ngx_http_limit_req_ctx_t

    return NGX_CONF_OK;
}

//对指令 limit_req 指令进行解析，判断出设置的共享内存名字，将其挂到 ngx_http_limit_req_limit_t 的 limits 数组
//例如： limit_req zone=one burst=5;
static char *
ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_req_conf_t  *lrcf = conf;

    ngx_int_t                    burst;
    ngx_str_t                   *value, s;
    ngx_uint_t                   i, nodelay;
    ngx_shm_zone_t              *shm_zone;
    ngx_http_limit_req_limit_t  *limit, *limits;

    value = cf->args->elts;

    shm_zone = NULL;
    burst = 0;
    nodelay = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        //zone=one
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            /* 
             * 如果这条 limit_req 指令在对应声明共享内存的 limit_req_zone 指令
             * 之前的话，这里也会先创建好这个 shm_zone, 下次执行到相应的
             * limit_req_zone 指令，只是把 size 改变了下
             * 反之如果 limit_req_zone 先执行，这次操作就是从 cycle->shared_memory
             * 上面把对应的 shm_zone 拿下来而已
             */
            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                             &ngx_http_limit_req_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        //burst=5
        if (ngx_strncmp(value[i].data, "burst=", 6) == 0) {

            //解析 burst，这个“域”允许的最大突发请求数
            burst = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (burst <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid burst rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        //解析 是否指定了nodelay
        if (ngx_strcmp(value[i].data, "nodelay") == 0) {
            nodelay = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    limits = lrcf->limits.elts;

    if (limits == NULL) {
        if (ngx_array_init(&lrcf->limits, cf->pool, 1,
                           sizeof(ngx_http_limit_req_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    //假如 limit_req 重复指定一块相同的共享内存（由 limit_req_zone 指令指定），则会返回错误
    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    //向limits数组中添加一条 保存ngx_http_limit_req_limit_t 记录
    limit = ngx_array_push(&lrcf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    //到时候会把 shm_zone->data 指向 ngx_http_limit_req_ctx_t
    //这样就和 ngx_http_limit_req_ctx_t 联系起来了
    limit->shm_zone = shm_zone; 
    limit->burst = burst * 1000;
    limit->nodelay = nodelay;

    return NGX_CONF_OK;
}

//设置钩子函数 ngx_http_limit_req_handler 到 ngx_http_core_main_conf 的 phases 数组里（NGX_HTTP_PREACCESS_PHASE）
static ngx_int_t
ngx_http_limit_req_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_req_handler;

    return NGX_OK;
}
