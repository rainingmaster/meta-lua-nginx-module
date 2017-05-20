
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_META_LUA_SHDICT_H_
#define _NGX_META_LUA_SHDICT_H_


#include "ngx_meta_lua_common.h"


typedef struct {
    u_char                       color;
    uint8_t                      value_type;
    u_short                      key_len;
    uint32_t                     value_len;
    uint64_t                     expires;
    ngx_queue_t                  queue;
    uint32_t                     user_flags;
    u_char                       data[1];
} ngx_meta_lua_shdict_node_t;


typedef struct {
    ngx_queue_t                  queue;
    uint32_t                     value_len;
    uint8_t                      value_type;
    u_char                       data[1];
} ngx_meta_lua_shdict_list_node_t;


typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   lru_queue;
} ngx_meta_lua_shdict_shctx_t;


typedef struct {
    ngx_meta_lua_shdict_shctx_t    *sh;
    ngx_slab_pool_t                *shpool;
    ngx_str_t                       name;
    ngx_log_t                      *log;
} ngx_meta_lua_shdict_ctx_t;


typedef struct {
    ngx_shm_zone_t               zone;
    ngx_meta_lua_conf_t         *mlcf;
} ngx_meta_lua_shm_zone_ctx_t;


#define ngx_meta_lua_SHDICT_ADD         0x0001
#define ngx_meta_lua_SHDICT_REPLACE     0x0002
#define ngx_meta_lua_SHDICT_SAFE_STORE  0x0004


enum {
    SHDICT_TNIL = 0,        /* same as LUA_TNIL */
    SHDICT_TBOOLEAN = 1,    /* same as LUA_TBOOLEAN */
    SHDICT_TNUMBER = 3,     /* same as LUA_TNUMBER */
    SHDICT_TSTRING = 4,     /* same as LUA_TSTRING */
    SHDICT_TLIST = 5,
};


#endif /* _NGX_META_LUA_SHDICT_H_ */
