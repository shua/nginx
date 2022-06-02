
#ifndef _NGX_EVENT_TLS_H_INCLUDED_
#define _NGX_EVENT_TLS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <tls.h>

typedef struct {
    struct tls *tls;
    ngx_log_t *log;
} ngx_tls_t;

struct ngx_tls_connection_s {
    struct tls *ctx;
    void       *handler;

    ngx_event_handler_pt  saved_read_handler;
    ngx_event_handler_pt  saved_write_handler;

    unsigned handshaked : 1;
    unsigned no_wait_shutdown : 1;
};

typedef struct ngx_tls_connection_s ngx_tls_connection_t;

ngx_int_t ngx_tls_create_connection(ngx_tls_t *tls, ngx_connection_t *c);
ngx_int_t ngx_tls_handshake(ngx_connection_t *c);

ssize_t ngx_tls_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_tls_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
ssize_t ngx_tls_send(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t* ngx_tls_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
#endif // _NGX_EVENT_TLS_H_INCLUDED_
