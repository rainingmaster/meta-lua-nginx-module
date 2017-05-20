
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_META_LUA_COMMON_H_
#define _NGX_META_LUA_COMMON_H_


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


typedef struct {
    ngx_array_t     *init_hooks;

    ngx_array_t     *shm_zones;
    ngx_uint_t       shm_zones_inited;
} ngx_meta_lua_conf_t;


extern ngx_module_t ngx_meta_lua_module;


#endif /* _NGX_META_LUA_COMMON_H_ */
