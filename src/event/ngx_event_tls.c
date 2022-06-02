#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

ngx_int_t
ngx_tls_handshake(ngx_connection_t *c)
{
    int rv;
    for (rv = TLS_WANT_POLLIN; rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT;) {
        rv = tls_handshake(c->tls->ctx);
    }
    if (rv == -1) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "ngx_tls_handshake() failed");
        return NGX_ERROR;
    }

    // not sure why we do this, but ssl code does it
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    c->recv = ngx_tls_recv;
    c->send = ngx_tls_send;
    c->recv_chain = ngx_tls_recv_chain;
    c->send_chain = ngx_tls_send_chain;

    c->read->ready = 1;
    c->write->ready = 1;

    c->tls->handshaked = 1;

    return NGX_OK;
}

ngx_int_t
ngx_tls_create_connection(ngx_tls_t *tls, ngx_connection_t *c) {
    ngx_tls_connection_t *tc;
    tc = ngx_pcalloc(c->pool, sizeof(ngx_tls_connection_t));
    if (tc == NULL)
        return NGX_ERROR;

    if (tls_accept_socket(tls->tls, &tc->ctx, c->fd) == -1) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "ngx_tls_create_connection() tls_accept_socket failed");
        return NGX_ERROR;
    }

    c->tls = tc;
    return NGX_OK;
}

ssize_t
ngx_tls_recv(ngx_connection_t *c, u_char *buf, size_t size) {
    for (int n = 0, bytes = 0; size > 0; (size -= n, buf += n, bytes += n)) {
        n = tls_read(c->tls->ctx, buf, size);
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_read: %d", n);
        if (n == 0) {
            return bytes;
        } else if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT) {
            if (bytes == 0) {
                n = 0;
                continue;
            }
            c->read->ready = 0;
            c->write->ready = 0;
            return bytes;
        } else if (n < 0) {
            c->read->error = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_read err: %s", tls_error(c->tls->ctx));
            return NGX_ERROR;
        }
    }
    // size <= 0
    return NGX_AGAIN;
}

ssize_t
ngx_tls_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit) {
    u_char     *last;
    ssize_t     n, bytes = 0, size;
    ngx_buf_t  *b;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_tls_recv_chain(%p, %p, %d)", c, cl, limit);

    for (; cl; cl = cl->next) {
        b = cl->buf;
        size = b->end - b->last;
        if (limit != 0) {
            if (bytes >= limit) {
                return bytes;
            }

            if (bytes + size > limit) {
                size = (ssize_t) (limit - bytes);
            }
        }

        for (u_char *last = b->last; last < b->end; last += n) {
            n = ngx_tls_recv(c, last, size);
            if (n < 0) {
                if (bytes != 0)
                    return bytes;
                return n;
            }
            bytes += n;
            size -= n;
            if (size <= 0) {
                return bytes;
            }
            if (!c->read->ready) {
                return bytes;
            }
        }
    }
    return bytes;
}

ssize_t
ngx_tls_send(ngx_connection_t *c, u_char *buf, size_t size) {
    ssize_t bytes = 0;
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_write: %d", size);
    for (ssize_t n = 0; size > 0; (size -= n, buf += n, bytes += n)) {
        n = tls_write(c->tls->ctx, buf, size);
        if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT) {
            if (bytes == 0) {
                n = 0;
                continue;
            }

            c->write->ready = 0;
            c->read->ready = 1;

            return bytes;
        } else if (n < 0) {
            c->write->error = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_write err: %s", tls_error(c->tls->ctx));
            return NGX_ERROR;
        }
    }
    return bytes;
}

ngx_chain_t*
ngx_tls_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit) {
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_tls_send_chain(%p, %p, %d)", c, in, limit);
    ssize_t n;
    while (in) {
        if (ngx_buf_special(in->buf)) {
            in = in->next;
            continue;
        }
        n = ngx_tls_send(c, in->buf->pos, in->buf->last - in->buf->pos);
        if (n == NGX_ERROR)
            return NGX_CHAIN_ERROR;
        if (n == NGX_AGAIN)
            return in;
        in->buf->pos += n;
        if (in->buf->pos == in->buf->last)
            in = in->next;
    }
    return in;
}
