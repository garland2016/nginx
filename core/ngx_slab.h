
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

struct ngx_slab_page_s {
    uintptr_t         slab;         //多用途
    ngx_slab_page_t  *next;         //指向下一页
    uintptr_t         prev;         //指向上一页
};


typedef struct {
    ngx_shmtx_sh_t    lock;         //为ngx_shmtx_t mutex服务

    size_t            min_size;     //设定的最小内存块长度
    size_t            min_shift;

    ngx_slab_page_t  *pages;        //每一页对应一个ngx_slab_page_t，这个pages是所有页的数组首指针
    ngx_slab_page_t  *last;
    ngx_slab_page_t   free;         //空闲页链表

    u_char           *start;        //这段共享内存的开始地址
    u_char           *end;          //这段共享内存的尾部地址

    ngx_shmtx_t       mutex;        //nginx封装的互斥锁

    u_char           *log_ctx;      //记录出错日志用的字符串
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;
} ngx_slab_pool_t;


void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
