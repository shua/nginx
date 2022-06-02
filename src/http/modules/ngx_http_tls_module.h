#ifndef _NGX_HTTP_TLS_MODULE_H_INCLUDED_
#define _NGX_HTTP_TLS_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_tls_srv_conf_s {
    ngx_flag_t           enable;
    ngx_tls_t            tls;

    ngx_str_t            root_certificate;
    ngx_str_t            certificate;
    ngx_str_t            certificate_key;
    ngx_str_t            crl;

    u_char              *file;
    ngx_uint_t           line;
} ngx_http_tls_srv_conf_t;

extern ngx_module_t ngx_http_tls_module;

#endif // _NGX_HTTP_TLS_MODULE_H_INCLUDED_
