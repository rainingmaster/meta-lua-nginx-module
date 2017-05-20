
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_META_LUA_API_H_INCLUDED_
#define _NGX_META_LUA_API_H_INCLUDED_


#include <nginx.h>
#include <ngx_core.h>

#include <stdint.h>


/* Public API for other ngx_lua modules */


#define ngx_meta_lua_version  10009


typedef ngx_int_t (*ngx_meta_lua_init_handler_pt)(ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_meta_lua_init_handler_pt        init_hook;
    ngx_cycle_t                        *cycle;
    void                               *data;
} ngx_meta_lua_init_hook_t;


ngx_shm_zone_t *ngx_meta_lua_find_zone(u_char *name_data, size_t name_len);

ngx_shm_zone_t *ngx_meta_lua_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);

ngx_int_t ngx_meta_lua_add_init_hooker(ngx_meta_lua_init_handler_pt func, ngx_cycle_t *cycle,
    void *args);

ngx_int_t ngx_meta_lua_shared_memory_count(ngx_conf_t *cf);


#endif /* _NGX_META_LUA_API_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
