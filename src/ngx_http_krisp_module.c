/*
 * @file:    ngx_http_krisp_module.c
 * @brief:   krisp(korea isp) database connect module
 * @author:  YoungJoo.Kim <vozlt@vozlt.com>
 * @version:
 * @date:
 *
 * Requires:
 *      libkrisp
 *
 * Compile:
 *      shell> ./configure --add-module=/path/to/nginx-module-krisp
 *
 * This module is mixed with ngx_http_realip_module.c from nginx-1.7.8.
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <krisp.h>

#define NGX_HTTP_KRISP_XREALIP  0
#define NGX_HTTP_KRISP_XFWD     1
#define NGX_HTTP_KRISP_HEADER   2
#define NGX_HTTP_KRISP_PROXY    3

typedef struct {
    ngx_array_t       *from;     /* array of ngx_cidr_t */
    ngx_uint_t         type;
    ngx_uint_t         hash;
    ngx_str_t          header;
    ngx_flag_t         recursive;
} ngx_http_krisp_loc_conf_t;


typedef struct {
    ngx_connection_t    *connection;
    struct sockaddr     *sockaddr;
    socklen_t           socklen;
    ngx_str_t           addr_text;
} ngx_http_krisp_ctx_t;


typedef struct {
    KR_API      *db;
    KRNET_API   isp;
    time_t      interval;
} ngx_http_krisp_conf_t; 


static ngx_int_t ngx_http_krisp_variable(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_krisp_x_variable(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_krisp_add_variables(ngx_conf_t *cf);
static void *ngx_http_krisp_create_conf(ngx_conf_t *cf);
static char *ngx_http_krisp_init_conf(ngx_conf_t *cf, void *conf);
static void ngx_http_krisp_cleanup(void *data);

static void *ngx_http_krisp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_krisp_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);
static char *ngx_http_krisp_database(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char *ngx_http_krisp_database_interval(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);

static char *ngx_http_krisp_realip_from(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char *ngx_http_krisp_realip(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_krisp_realip_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_krisp_realip_set_addr(ngx_http_request_t *r,
        ngx_addr_t *addr);
static void ngx_http_krisp_realip_cleanup(void *data);
static ngx_int_t ngx_http_krisp_init(ngx_conf_t *cf);


static ngx_http_variable_t  ngx_http_krisp_vars[] = {

    { ngx_string("krisp_check_ip"), NULL,
        ngx_http_krisp_variable,
        offsetof(KRNET_API, ip), 0, 0 },

    { ngx_string("krisp_isp_code"), NULL,
        ngx_http_krisp_variable,
        offsetof(KRNET_API, icode), 0, 0 },

    { ngx_string("krisp_isp_name"), NULL,
        ngx_http_krisp_variable,
        offsetof(KRNET_API, iname), 0, 0 },

    { ngx_string("krisp_country_code"), NULL,
        ngx_http_krisp_variable,
        offsetof(KRNET_API, ccode), 0, 0 },

    { ngx_string("krisp_country_name"), NULL,
        ngx_http_krisp_variable,
        offsetof(KRNET_API, cname), 0, 0 },

    { ngx_string("krisp_original_ip"), NULL,
        ngx_http_krisp_x_variable,
        offsetof(KRNET_API, cname), 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t  ngx_http_krisp_commands[] = {

    /* set database path */
    { ngx_string("krisp_database"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
        ngx_http_krisp_database,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    /* set database mtime check interval */
    { ngx_string("krisp_database_interval"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
        ngx_http_krisp_database_interval,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    /* set proxy real ip from */
    { ngx_string("krisp_real_ip_from"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_krisp_realip_from,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    /* set proxy real ip header */
    { ngx_string("krisp_real_ip_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_krisp_realip,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    /* set recursive search */
    { ngx_string("krisp_real_ip_recursive"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_krisp_loc_conf_t, recursive),
        NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_krisp_module_ctx = {
    ngx_http_krisp_add_variables,                /* preconfiguration */
    ngx_http_krisp_init,                         /* postconfiguration */

    ngx_http_krisp_create_conf,                  /* create main configuration */
    ngx_http_krisp_init_conf,                    /* init main configuration */

    NULL,                                        /* create server configuration */
    NULL,                                        /* merge server configuration */

    ngx_http_krisp_create_loc_conf,              /* create location configuration */
    ngx_http_krisp_merge_loc_conf,               /* merge location configuration */
};


ngx_module_t  ngx_http_krisp_module = {
    NGX_MODULE_V1,
    &ngx_http_krisp_module_ctx,                  /* module context */
    ngx_http_krisp_commands,                     /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_krisp_realip_handler(ngx_http_request_t *r)
{
    u_char                      *p;
    size_t                      len;
    ngx_str_t                   *value;
    ngx_uint_t                  i, hash;
    ngx_addr_t                  addr;
    ngx_array_t                 *xfwd;
    ngx_list_part_t             *part;
    ngx_table_elt_t             *header;
    ngx_connection_t            *c;
    ngx_http_krisp_ctx_t        *ctx;
    ngx_http_krisp_loc_conf_t   *klcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_krisp_module);

    if (ctx) {
        return NGX_DECLINED;
    }

    klcf = ngx_http_get_module_loc_conf(r, ngx_http_krisp_module);

    if (klcf->from == NULL) {
        return NGX_DECLINED;
    }

    switch (klcf->type) {

        case NGX_HTTP_KRISP_XREALIP:

            if (r->headers_in.x_real_ip == NULL) {
                return NGX_DECLINED;
            }

            value = &r->headers_in.x_real_ip->value;
            xfwd = NULL;

            break;

        case NGX_HTTP_KRISP_XFWD:

            xfwd = &r->headers_in.x_forwarded_for;

            if (xfwd->elts == NULL) {
                return NGX_DECLINED;
            }

            value = NULL;

            break;

        case NGX_HTTP_KRISP_PROXY:

            value = &r->connection->proxy_protocol_addr;

            if (value->len == 0) {
                return NGX_DECLINED;
            }

            xfwd = NULL;

            break;

        default: /* NGX_HTTP_KRISP_HEADER */

            part = &r->headers_in.headers.part;
            header = part->elts;

            hash = klcf->hash;
            len = klcf->header.len;
            p = klcf->header.data;

            for (i = 0; /* void */ ; i++) {

                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    header = part->elts;
                    i = 0;
                }

                if (hash == header[i].hash
                        && len == header[i].key.len
                        && ngx_strncmp(p, header[i].lowcase_key, len) == 0)
                {
                    value = &header[i].value;
                    xfwd = NULL;

                    goto found;
                }
            }

            return NGX_DECLINED;
    }

found:

    c = r->connection;

    addr.sockaddr = c->sockaddr;
    addr.socklen = c->socklen;
    /* addr.name = c->addr_text; */

    if (ngx_http_get_forwarded_addr(r, &addr, xfwd, value, klcf->from,
                klcf->recursive)
            != NGX_DECLINED)
    {
        return ngx_http_krisp_realip_set_addr(r, &addr);
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_krisp_realip_set_addr(ngx_http_request_t *r, ngx_addr_t *addr)
{
    size_t                  len;
    u_char                  *p;
    u_char                  text[NGX_SOCKADDR_STRLEN];
    ngx_connection_t        *c;
    ngx_pool_cleanup_t      *cln;
    ngx_http_krisp_ctx_t    *ctx;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_krisp_ctx_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;
    ngx_http_set_ctx(r, ctx, ngx_http_krisp_module);

    c = r->connection;

    len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
            NGX_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(p, text, len);

    cln->handler = ngx_http_krisp_realip_cleanup;

    ctx->connection = c;
    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NGX_DECLINED;
}


static void
ngx_http_krisp_realip_cleanup(void *data)
{   
    ngx_http_krisp_ctx_t *ctx = data;

    ngx_connection_t *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}


static void *
ngx_http_krisp_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_krisp_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_krisp_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = NGX_CONF_UNSET_UINT;
    conf->recursive = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_krisp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{   
    ngx_http_krisp_loc_conf_t *prev = parent;
    ngx_http_krisp_loc_conf_t *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    ngx_conf_merge_uint_value(conf->type, prev->type, NGX_HTTP_KRISP_XREALIP);
    ngx_conf_merge_value(conf->recursive, prev->recursive, 0);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_krisp_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_file_info_t     fi;
    ngx_str_t           *value;
    u_char              err[1024];

    ngx_http_krisp_conf_t *kcf = conf;

    if (kcf->db) {
        return "is duplicate";
    }

    kcf->db = NULL;

    value = cf->args->elts;

    if (ngx_file_info(value[1].data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                ngx_file_info_n " \"%s\" failed", value[1].data);
        return NGX_CONF_ERROR;
    }

    if (kr_open(&(kcf->db), (char *)value[1].data, (char *)err) == false) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "kr_open(\"%V\") failed", &value[1]);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

    
static char *
ngx_http_krisp_database_interval(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   *value;

    ngx_http_krisp_conf_t *kcf = conf;

    value = cf->args->elts;

    kcf->interval = (time_t) ngx_atoi(value[1].data, value[1].len);

    return NGX_CONF_OK;
}


static char *
ngx_http_krisp_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_krisp_loc_conf_t *klcf = conf;

    ngx_int_t   rc;
    ngx_str_t   *value;
    ngx_cidr_t  *cidr;

    value = cf->args->elts;

    if (klcf->from == NULL) {
        klcf->from = ngx_array_create(cf->pool, 2,
                sizeof(ngx_cidr_t));
        if (klcf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cidr = ngx_array_push(klcf->from);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "low address bits of %V are meaningless", &value[1]);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_krisp_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_krisp_loc_conf_t *klcf = conf;

    ngx_str_t *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "X-Real-IP") == 0) {
        klcf->type = NGX_HTTP_KRISP_XREALIP;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        klcf->type = NGX_HTTP_KRISP_XFWD;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "proxy_protocol") == 0) {
        klcf->type = NGX_HTTP_KRISP_PROXY;
        return NGX_CONF_OK;
    }

    klcf->type = NGX_HTTP_KRISP_HEADER;
    klcf->hash = ngx_hash_strlow(value[1].data, value[1].data, value[1].len);
    klcf->header = value[1];

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_krisp_variable(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                  *val;
    KRNET_API               isp;
    ngx_http_krisp_conf_t   *kcf;

    kcf = ngx_http_get_module_main_conf(r, ngx_http_krisp_module);

    if (kcf->db == NULL) {
        goto not_found;
    }

    if (ngx_strncmp((char *)r->connection->addr_text.data, kcf->isp.ip, r->connection->addr_text.len) == 0) {
        goto data_ready;
    }

    ngx_cpystrn((u_char *)isp.ip, (u_char *)r->connection->addr_text.data, r->connection->addr_text.len + 1);

    isp.verbose = false;
    if (kr_search (&isp, kcf->db)) {
        goto not_found;
    }
    kcf->isp = isp;

data_ready:
    val =  (u_char *) &kcf->isp + data;

    v->len = ngx_strlen(val);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = val;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_krisp_x_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_krisp_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_krisp_module);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (!ctx) {
        goto not_found;
    }

    v->len = ctx->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->addr_text.data;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_krisp_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_krisp_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_krisp_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t      *cln;
    ngx_http_krisp_conf_t   *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_krisp_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->interval = NGX_CONF_UNSET;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_krisp_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_krisp_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_krisp_conf_t *kcf = conf;

    if (kcf->db) {
        ngx_conf_init_value(kcf->interval, 0);
        kcf->db->db_time_stamp_interval = kcf->interval;
    }

    return NGX_CONF_OK;
}


static void
ngx_http_krisp_cleanup(void *data)
{
    ngx_http_krisp_conf_t *kcf = data;

    kr_close(&(kcf->db));
}


static ngx_int_t
ngx_http_krisp_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_krisp_realip_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_krisp_realip_handler;

    return NGX_OK;
}
