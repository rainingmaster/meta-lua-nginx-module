
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#include "api/ngx_meta_lua_api.h"
#include "ngx_meta_lua_common.h"
#include "ngx_meta_lua_shdict.h"


static ngx_int_t ngx_meta_lua_shared_memory_init(ngx_shm_zone_t *shm_zone,
    void *data);

ngx_shm_zone_t *
ngx_meta_lua_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name, size_t size,
    void *tag)
{
    ngx_meta_lua_conf_t          *mlcf;
    ngx_shm_zone_t              **zp;
    ngx_shm_zone_t               *zone;
    ngx_meta_lua_shm_zone_ctx_t  *ctx;
    ngx_int_t                     n;

    mlcf = (ngx_meta_lua_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                ngx_meta_lua_module);

    if (mlcf == NULL) {
        return NULL;
    }

    if (mlcf->shm_zones == NULL) {
        mlcf->shm_zones =
            ngx_array_create(cf->pool, 1,
                             sizeof(ngx_shm_zone_t *));

        if (mlcf->shm_zones == NULL) {
            return NULL;
        }
    }

    zone = ngx_shared_memory_add(cf, name, (size_t) size, tag);
    if (zone == NULL) {
        return NULL;
    }

    if (zone->data) {
        ctx = (ngx_meta_lua_shm_zone_ctx_t *) zone->data;
        return &ctx->zone;
    }

    n = sizeof(ngx_meta_lua_shm_zone_ctx_t);

    ctx = ngx_pcalloc(cf->pool, n);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->mlcf = mlcf;

    ngx_memcpy(&ctx->zone, zone, sizeof(ngx_shm_zone_t));

    zp = ngx_array_push(mlcf->shm_zones);
    if (zp == NULL) {
        return NULL;
    }

    *zp = zone;

    /* set zone init */
    zone->init = ngx_meta_lua_shared_memory_init;
    zone->data = ctx;

    return &ctx->zone;
}


static ngx_int_t
ngx_meta_lua_shared_memory_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_meta_lua_shm_zone_ctx_t *octx = data;
    ngx_shm_zone_t              *ozone;
    void                        *odata;

    ngx_int_t                    rc;
    ngx_uint_t                   i;
    ngx_meta_lua_conf_t         *mlcf;
    ngx_meta_lua_init_hook_t    *hook;
    ngx_meta_lua_shm_zone_ctx_t *ctx;
    ngx_shm_zone_t              *zone;

    ctx = (ngx_meta_lua_shm_zone_ctx_t *) shm_zone->data;
    zone = &ctx->zone;

    odata = NULL;
    if (octx) {
        ozone = &octx->zone;
        odata = ozone->data;
    }

    zone->shm = shm_zone->shm;
#if defined(nginx_version) && nginx_version >= 1009000
    zone->noreuse = shm_zone->noreuse;
#endif

    if (zone->init(zone, odata) != NGX_OK) {
        return NGX_ERROR;
    }

    dd("get mlcf");

    mlcf = ctx->mlcf;
    if (mlcf == NULL) {
        return NGX_ERROR;
    }

    dd("mlcf->lua: %p", mlcf->lua);

    mlcf->shm_zones_inited++;

    if (mlcf->shm_zones_inited == mlcf->shm_zones->nelts
        && mlcf->init_hooks)
    {
        hook = mlcf->init_hooks->elts;

        for (i = 0; i < mlcf->init_hooks->nelts; i++) {
            rc = hook[i].init_hook(hook[i].cycle, hook[i].data);

            if (rc != NGX_OK) {
                /* an error happened */
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


ngx_shm_zone_t *
ngx_meta_lua_find_zone(u_char *name_data, size_t name_len)
{
    ngx_str_t                       *name;
    ngx_uint_t                       i;
    ngx_shm_zone_t                  *zone;
    ngx_meta_lua_shm_zone_ctx_t     *ctx;
    volatile ngx_list_part_t        *part;

    part = &ngx_cycle->shared_memory.part;
    zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            zone = part->elts;
            i = 0;
        }

        name = &zone[i].shm.name;

        dd("name: [%.*s] %d", (int) name->len, name->data, (int) name->len);
        dd("name2: [%.*s] %d", (int) name_len, name_data, (int) name_len);

        if (name->len == name_len
            && ngx_strncmp(name->data, name_data, name_len) == 0)
        {
            ctx = (ngx_meta_lua_shm_zone_ctx_t *) zone[i].data;
            return &ctx->zone;
        }
    }

    return NULL;
}


ngx_int_t
ngx_meta_lua_add_init_hooker(ngx_meta_lua_init_handler_pt func, ngx_cycle_t *cycle,
    void *args)
{
    ngx_meta_lua_conf_t          *mlcf;
    ngx_meta_lua_init_hook_t     *hook;

    mlcf = (ngx_meta_lua_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                ngx_meta_lua_module);

    if (mlcf == NULL) {
        return NGX_ERROR;
    }

    if (mlcf->init_hooks == NULL) {
        mlcf->init_hooks =
            ngx_array_create(cycle->pool, 1,
                             sizeof(ngx_meta_lua_init_hook_t));

        if (mlcf->init_hooks == NULL) {
            return NGX_ERROR;
        }
    }

    hook = ngx_array_push(mlcf->init_hooks);
    if (hook == NULL) {
        return NGX_ERROR;
    }

    hook->init_hook = func;
    hook->cycle = cycle;
    hook->data = args;

    return NGX_OK;

}


ngx_int_t
ngx_meta_lua_shared_memory_count(ngx_conf_t *cf)
{
    ngx_meta_lua_conf_t          *mlcf;

    mlcf = (ngx_meta_lua_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                ngx_meta_lua_module);

    if (mlcf == NULL) {
        return NGX_ERROR;
    }

    if (mlcf->shm_zones == NULL) {
        return 0;
    }

    return mlcf->shm_zones->nelts;
}
