
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    u_char                     color;
    u_char                     len;
    u_short                    conn;
    u_char                     data[1];
} ngx_http_limit_conn_node_t;


typedef struct {
    ngx_shm_zone_t            *shm_zone;
    ngx_rbtree_node_t         *node;
} ngx_http_limit_conn_cleanup_t;


typedef struct {
    ngx_rbtree_t              *rbtree;
    ngx_http_complex_value_t   key;
} ngx_http_limit_conn_ctx_t;


typedef struct {
    ngx_shm_zone_t            *shm_zone;
    ngx_uint_t                 conn;
} ngx_http_limit_conn_limit_t;


typedef struct {
    ngx_array_t                limits;
    ngx_uint_t                 log_level;
    ngx_uint_t                 status_code;
} ngx_http_limit_conn_conf_t;


static ngx_rbtree_node_t *ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree,
    ngx_str_t *key, uint32_t hash);
static void ngx_http_limit_conn_cleanup(void *data);
static ngx_inline void ngx_http_limit_conn_cleanup_all(ngx_pool_t *pool);

static void *ngx_http_limit_conn_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_conn_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_limit_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_limit_conn_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t  ngx_http_limit_conn_commands[] = {

    { ngx_string("limit_conn_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn_zone,
      NGX_HTTP_LOC_CONF_OFFSET,     /*
                                    根据cmd->conf的值从cf->ctx中取出对应的配置。
                                    举http模块为例，cf->conf的可选值是
                                    NGX_HTTP_MAIN_CONF_OFFSET、
                                    NGX_HTTP_SRV_CONF_OFFSET、
                                    NGX_HTTP_LOC_CONF_OFFSET，分别对应“http{}”、“server{}”、“location{}”这三个http配置级别。
                                    */
      0,
      NULL },

    { ngx_string("limit_conn"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_conn_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, log_level),
      &ngx_http_limit_conn_log_levels },

    { ngx_string("limit_conn_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, status_code),
      &ngx_http_limit_conn_status_bounds },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_conn_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_limit_conn_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_conn_create_conf,       /* create location configuration */
    ngx_http_limit_conn_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_limit_conn_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_conn_module_ctx,       /* module context */
    ngx_http_limit_conn_commands,          /* module directives */
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
ngx_http_limit_conn_handler(ngx_http_request_t *r)
{
    size_t                          n;
    uint32_t                        hash;
    ngx_str_t                       key;
    ngx_uint_t                      i;
    ngx_slab_pool_t                *shpool;
    ngx_rbtree_node_t              *node;
    ngx_pool_cleanup_t             *cln;
    ngx_http_limit_conn_ctx_t      *ctx;
    ngx_http_limit_conn_node_t     *lc;
    ngx_http_limit_conn_conf_t     *lccf;
    ngx_http_limit_conn_limit_t    *limits;
    ngx_http_limit_conn_cleanup_t  *lccln;

    if (r->main->limit_conn_set) {
        return NGX_DECLINED;
    }

    lccf = ngx_http_get_module_loc_conf(r, ngx_http_limit_conn_module);
    
    //取出限制数组
    limits = lccf->limits.elts;

    for (i = 0; i < lccf->limits.nelts; i++) {

        //处理每一条limit_conn策略
        ctx = limits[i].shm_zone->data;

        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        r->main->limit_conn_set = 1;

        hash = ngx_crc32_short(key.data, key.len);

        //取出这个共享内存的首地址
        shpool = (ngx_slab_pool_t *) limits[i].shm_zone->shm.addr;

        ngx_shmtx_lock(&shpool->mutex);

        //根据KEY在rbtree中查找节点
        node = ngx_http_limit_conn_lookup(ctx->rbtree, &key, hash);

        if (node == NULL) {

            //若没有找到结点，说明是这个key的第一个请求
            //内存结构是： ngx_rbtree_node_t + ngx_http_limit_conn_node_t + key
            n = offsetof(ngx_rbtree_node_t, color)
                + offsetof(ngx_http_limit_conn_node_t, data)
                + key.len;

            //从共享内存中分配n个字节大小的内存
            node = ngx_slab_alloc_locked(shpool, n);

            //根本共享内存失败
            if (node == NULL) {
                ngx_shmtx_unlock(&shpool->mutex);
                ngx_http_limit_conn_cleanup_all(r->pool);
                return lccf->status_code;
            }

            //从rbtree结点node的color成员取出 limit_conn_code的地址
            lc = (ngx_http_limit_conn_node_t *) &node->color;

            node->key = hash;   //给红黑树的key 赋值
            lc->len = (u_char) key.len;
            lc->conn = 1;       //连接数置为1
            ngx_memcpy(lc->data, key.data, key.len);        //把key 拷贝到 ngx_http_limit_conn_node_t 的data成员中

            //向红黑树中插入新结点
            ngx_rbtree_insert(ctx->rbtree, node);

        } 
        else {

            //从rbtree结点node的color成员取出 limit_conn_code的地址
            lc = (ngx_http_limit_conn_node_t *) &node->color;

            if ((ngx_uint_t) lc->conn >= limits[i].conn) {
                
                //如果连接数已经大于等于设置的限制的值了
                ngx_shmtx_unlock(&shpool->mutex);

                ngx_log_error(lccf->log_level, r->connection->log, 0,
                              "limiting connections by zone \"%V\"",
                              &limits[i].shm_zone->shm.name);

                ngx_http_limit_conn_cleanup_all(r->pool);
                return lccf->status_code;   //拒绝请求
            }

            lc->conn++; //否则将节点中存储的连接数加1
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        ngx_shmtx_unlock(&shpool->mutex);

        //若请求通过了策略，请求结束时则应该将连接数减1。模块将这逻辑的处理函数注册到请求的内存池销毁阶段
        cln = ngx_pool_cleanup_add(r->pool,
                                   sizeof(ngx_http_limit_conn_cleanup_t));
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_http_limit_conn_cleanup;     //函数的参数就是cln->data
        lccln = cln->data;

        lccln->shm_zone = limits[i].shm_zone;   //指定共享内存区域
        lccln->node = node;                     //指定红黑树的结点
    }

    return NGX_DECLINED;
}


static void
ngx_http_limit_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_limit_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_http_limit_conn_node_t *) &node->color;
            lcnt = (ngx_http_limit_conn_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
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
    ngx_rbt_red(node);
}


static ngx_rbtree_node_t *
ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_limit_conn_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

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

        lcn = (ngx_http_limit_conn_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_http_limit_conn_cleanup(void *data)
{
    ngx_http_limit_conn_cleanup_t  *lccln = data;       //取出参数

    ngx_slab_pool_t             *shpool;
    ngx_rbtree_node_t           *node;
    ngx_http_limit_conn_ctx_t   *ctx;
    ngx_http_limit_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;

    //取得共享内存的首地址，也是ngx_slab_pool_t的起始地址
    shpool = (ngx_slab_pool_t *) lccln->shm_zone->shm.addr;

    node = lccln->node;

    lc = (ngx_http_limit_conn_node_t *) &node->color;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    lc->conn--;     //将红黑树中的结点的请求数减减

    if (lc->conn == 0) {
        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);
}


static ngx_inline void
ngx_http_limit_conn_cleanup_all(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == ngx_http_limit_conn_cleanup) {
        ngx_http_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static ngx_int_t
ngx_http_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_conn_ctx_t  *octx = data;

    size_t                      len;
    ngx_slab_pool_t            *shpool;
    ngx_rbtree_node_t          *sentinel;
    ngx_http_limit_conn_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        ctx->rbtree = octx->rbtree;

        return NGX_OK;
    }

    //shm.addr里存放着共享内存的首地址：ngx_slab_pool_t结构体
    //用这个shpool来分配与释放共享内存
    //因为ngx_slab_pool_t结构体是在整个共享内存的地址的首位置
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;

        return NGX_OK;
    }

    //为共享内存分配内存空间
    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    //把刚分配好的内存地址 指向 ngx_slab_pool_t的data成员
    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_http_limit_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void *
ngx_http_limit_conn_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_conn_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_conn_conf_t *prev = parent;
    ngx_http_limit_conn_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_SERVICE_UNAVAILABLE);

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_uint_t                         i;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_limit_conn_ctx_t         *ctx;
    ngx_http_compile_complex_value_t   ccv;

    //ngx_http_limit_conn_conf_t *lccf = conf;
    //printf("ngx_http_limit_conn_zone  status_code = %ld log_level = %ld \r\n",lccf->status_code,lccf->log_level);

    value = cf->args->elts;         //limit_conn_zone $binary_remote_addr zone=limit:10m;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    //解析参数
    for (i = 2; i < cf->args->nelts; i++) {

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

            size = ngx_parse_size(&s);

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

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    //解析共享内存的名称
    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    //向系统注册一块共享内存，名字为:name 大小为：size
    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_conn_module);
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

    shm_zone->init = ngx_http_limit_conn_init_zone; //自定义的共享内存的初始化方法
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_shm_zone_t               *shm_zone;
    ngx_http_limit_conn_conf_t   *lccf = conf;
    ngx_http_limit_conn_limit_t  *limit, *limits;

    ngx_str_t  *value;
    ngx_int_t   n;
    ngx_uint_t  i;

    value = cf->args->elts;         //limit_conn limit 10;

    //printf("ngx_http_limit_conn  status_code = %ld log_level = %ld \r\n",lccf->status_code,lccf->log_level);
    
    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_http_limit_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    limits = lccf->limits.elts;
    //printf("name = %s lccf->limits.nelts = %ld \r\n",value[1].data,lccf->limits.nelts);

    //如果限制数组为空
    if (limits == NULL) {
        if (ngx_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(ngx_http_limit_conn_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    //遍历限制数组
    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {       //如果已经有这个shm_zone了
            return "is duplicate";
        }
    }

    //解析出限制连接的数量
    n = ngx_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (n > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NGX_CONF_ERROR;
    }

    //向限制数组中添加一项
    limit = ngx_array_push(&lccf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    limit->conn = n;            //设置限制的连接数
    limit->shm_zone = shm_zone; //设置这条限制的共享内存

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_limit_conn_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_conn_handler;

    //printf("cycle->conf_file = %s \r\ncycle->conf_param = %s \r\ncycle->conf->prefix = %s\r\n" 
    //        "cycle->prefix = %s\r\ncycle->hostname = %s \r\n",  
    //        cf->cycle->conf_file.data,cf->cycle->conf_param.data,cf->cycle->conf_prefix.data,
    //        cf->cycle->prefix.data,cf->cycle->hostname.data);

    return NGX_OK;
}
