
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#include "ngx_meta_lua_common.h"


static void *ngx_meta_lua_module_create_conf(ngx_cycle_t *cycle);


static ngx_core_module_t ngx_meta_lua_module_ctx = {
    ngx_string("meta_lua"),
    ngx_meta_lua_module_create_conf,
    NULL
};


ngx_module_t ngx_meta_lua_module = {
    NGX_MODULE_V1,
    &ngx_meta_lua_module_ctx,          /* module context */
    NULL,                              /* module directives */
    NGX_CORE_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_meta_lua_module_create_conf(ngx_cycle_t *cycle)
{
    ngx_meta_lua_conf_t  *mlcf;

    mlcf = ngx_pcalloc(cycle->pool, sizeof(ngx_meta_lua_conf_t));
    if (mlcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc()
     *
     * mlcf->init_hooks = NULL;
     * mlcf->shm_zones  = NULL;
     * mlcf->shm_zones_inited = 0;
     */

    return mlcf;
}
