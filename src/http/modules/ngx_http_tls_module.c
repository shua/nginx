
/*
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_tls_add_variables(ngx_conf_t *cf);
static void *ngx_http_tls_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_tls_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_tls_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_tls_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_tls_commands[] = {
    { ngx_string("tls"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_http_tls_enable,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_tls_srv_conf_t, enable),
      NULL },

    { ngx_string("tls_root_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_tls_srv_conf_t, root_certificate),
      NULL },

    { ngx_string("tls_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_tls_srv_conf_t, certificate),
      NULL },

    { ngx_string("tls_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_tls_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("tls_crl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_tls_srv_conf_t, crl),
      NULL },

};

static ngx_http_module_t  ngx_http_tls_module_ctx = {
    ngx_http_tls_add_variables,            /* preconfiguration */
    ngx_http_tls_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_tls_create_srv_conf,          /* create server configuration */
    ngx_http_tls_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_tls_module = {
    NGX_MODULE_V1,
    &ngx_http_tls_module_ctx,              /* module context */
    ngx_http_tls_commands,                 /* module directives */
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

static ngx_http_variable_t  ngx_http_tls_vars[] = {

      ngx_http_null_variable
};

static ngx_int_t
ngx_http_tls_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_tls_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
    return -1;
}

static void *
ngx_http_tls_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_tls_srv_conf_t *tscf;
    tscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tls_srv_conf_t));
    if (tscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc:
     *
     * tscf->tls = {0};
     * tscf->root_certificate = { 0, NULL };
     * tscf->certificate = { 0, NULL };
     * tscf->certificate_key = { 0, NULL };
     * tscf->file = NULL;
     * tscf->line = 0;
     */

    tscf->enable = NGX_CONF_UNSET;
    return tscf;
}

static char *
ngx_http_tls_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tls_srv_conf_t *p = parent;
    ngx_http_tls_srv_conf_t *c = child;

    if (c->enable == NGX_CONF_UNSET) {
        if (p->enable == NGX_CONF_UNSET) {
            c->enable = 0;
        } else {
            c->enable = p->enable;
            c->file = p->file;
            c->line = p->line;
        }
    }

    // is this valid or do we need to strcpy?
    if (c->root_certificate.data == NULL)
        c->root_certificate = p->root_certificate;
    if (c->crl.data == NULL)
        c->crl = p->crl;
    if (c->certificate.data == NULL)
        c->certificate = p->certificate;
    if (c->certificate_key.data == NULL)
        c->certificate_key = p->certificate_key;

    return NGX_CONF_OK;
}

static char *
ngx_http_tls_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tls_srv_conf_t *tscf = conf;

    char *rv;
    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    tscf->file = cf->conf_file->file.name.data;
    tscf->line = cf->conf_file->line;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_tls_init(ngx_conf_t *cf)
{
    ngx_uint_t                   s;
    ngx_http_tls_srv_conf_t     *tscf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (tls_init() == -1)
        ngx_log_error(NGX_LOG_EMERG, cf->log, errno, "tls_init failed");

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        tscf = cscfp[s]->ctx->srv_conf[ngx_http_tls_module.ctx_index];
        if (!tscf->enable)
            continue;

        if (tscf->tls.tls != NULL)
            continue;

        struct tls_config *cfg;
        if ((cfg = tls_config_new()) == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, errno, "tls_config_new failed");
            return NGX_ERROR;
        }
        if ((tscf->tls.tls = tls_server()) == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, errno, "tls_server failed");
            goto config_fail;
        }
        if (tscf->root_certificate.len != 0
                && tls_config_set_ca_file(cfg, (const char*)tscf->root_certificate.data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, errno, "tls set ca failed");
            goto config_fail;
        }
        if (tscf->crl.len != 0
                && tls_config_set_crl_file(cfg, (const char*)tscf->crl.data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, errno, "tls set crl failed");
            goto config_fail;
        }
        if (tscf->certificate.len != 0
                && tls_config_set_cert_file(cfg, (const char*)tscf->certificate.data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, errno, "tls set certificate failed");
            goto config_fail;
        }
        if (tscf->certificate_key.len != 0
                && tls_config_set_key_file(cfg, (const char*)tscf->certificate_key.data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, errno, "tls set certificate_key failed");
            goto config_fail;
        }

        if (tls_configure(tscf->tls.tls, cfg) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "tls configure failed: %s", tls_error(tscf->tls.tls));
            goto config_fail;
        }
        tscf->tls.log = cf->log;

        tls_config_free(cfg);
        cfg = NULL;

        continue;
config_fail:
        if (tscf->tls.tls != NULL) {
            tls_free(tscf->tls.tls);
            tscf->tls.tls = NULL;
        }
        if (cfg != NULL) {
            tls_config_free(cfg);
            cfg = NULL;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_tls_cleanup_ctx(void *data) {
    ngx_tls_t *tls = data;
    if (tls == NULL || tls->tls == NULL)
        return NGX_OK;

    tls_free(tls->tls);
    tls->tls = NULL;

    return NGX_OK;
}
