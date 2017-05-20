
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_META_LUA_SHDICT_H_
#define _NGX_META_LUA_SHDICT_H_


#include "ngx_meta_lua_common.h"


typedef struct {
    ngx_shm_zone_t               zone;
    ngx_meta_lua_conf_t         *mlcf;
} ngx_meta_lua_shm_zone_ctx_t;


#endif /* _NGX_META_LUA_SHDICT_H_ */
