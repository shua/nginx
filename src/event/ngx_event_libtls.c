
/*
 * Copyright (C) shua @ isthis.email
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

static void ngx_ssl_connection_close(void *data);
static ngx_int_t ngx_ssl_add_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_str_t *key);

ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
    if (tls_init() == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "failed to initialize tls");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_conf_create(ngx_conf_t *cf, ngx_ssl_conf_t **conf, void *data)
{
    *conf = tls_config_new();
    if (conf == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "failed to create ssl config");
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
ngx_ssl_conf_free(ngx_ssl_conf_t *conf)
{
    tls_config_free(conf);
}

ngx_int_t
ngx_ssl_create(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_ssl_conf_t *conf)
{
    /* TODO: tls client? is that only on upstream? */
    ssl->ctx = tls_server();
    if (ssl->ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "failed to initialize tls");
        return NGX_ERROR;
    }

    if (tls_configure(ssl->ctx, conf) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "failed to configure tls: %s",
                      tls_error(ssl->ctx));
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_ssl_cleanup_ctx(void *data)
{
    ngx_ssl_t *ssl;
    ssl = data;
    if (ssl == NULL)
        return;

    if (ssl->ctx != NULL) {
        tls_free(ssl->ctx);
        ssl->ctx = NULL;
    }
}


ngx_int_t
ngx_ssl_protocols(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_ssl_protocol_t protocols)
{
    if (protocols & (NGX_SSL_SSLv2 | NGX_SSL_SSLv3)) {
        ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                      "SSLv2 and SSLv3 protocols are not supported in this implementation");
    }

    ngx_uint_t tls_protocols =
        ((protocols & NGX_SSL_TLSv1) ? TLS_PROTOCOL_TLSv1_0 : 0)
        | ((protocols & NGX_SSL_TLSv1_1) ? TLS_PROTOCOL_TLSv1_1 : 0)
        | ((protocols & NGX_SSL_TLSv1_2) ? TLS_PROTOCOL_TLSv1_2 : 0)
        | ((protocols & NGX_SSL_TLSv1_3) ? TLS_PROTOCOL_TLSv1_3 : 0);
    if (tls_config_set_protocols(ssl, tls_protocols) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "failed setting protocols: %s",
                      tls_config_error(ssl));
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_certificate_values(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_array_t *certs, ngx_array_t *keys, ngx_array_t *passwords)
{
    ngx_str_t  *cert, *key;
    ngx_uint_t  i;

    if (certs == NGX_CONF_UNSET_PTR || certs == NULL || certs->nelts == 0) {
        return NGX_OK;
    }

    if (keys == NGX_CONF_UNSET_PTR || keys == NULL
        || certs->nelts != keys->nelts
    ) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "number of certs (%d) doesn't match number of keys (%d)",
                      certs->nelts, keys->nelts);
    }

    cert = certs->elts;
    key = keys->elts;
    for (i=0; i < certs->nelts && i < keys->nelts; i++) {
        if (tls_config_add_keypair_mem(ssl,
                                       cert[i].data, cert[i].len,
                                       key[i].data, key[i].len)
            == -1
        ) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "failed adding keypair");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_array_t *certs, ngx_array_t *keys, ngx_array_t *passwords)
{
    ngx_str_t  *cert, *key, conf_prefix;
    ngx_uint_t  i;

    if (passwords != NGX_CONF_UNSET_PTR && passwords != NULL
        && passwords->nelts != 0
    ) {
        /* TODO: decrypt with tls_load_file */
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "private key decryption not implemented");
        return NGX_ERROR;
    }

    conf_prefix = ngx_cycle->conf_prefix;
    cert = certs->elts;
    key = keys->elts;

    if (certs->nelts != keys->nelts) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "number of certs (%d) doesn't match number of keys (%d)",
                      certs->nelts, keys->nelts);
    }

    if (certs->nelts > 0) {
        if (ngx_get_full_name(cf->pool, &conf_prefix, cert) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_get_full_name(cf->pool, &conf_prefix, key) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_ssl_certificate(cf, ssl, &cert[0], &key[0], passwords)
            != NGX_OK
        ) {
            return NGX_ERROR;
        }
    }

    for (i = 1; i < certs->nelts && i < keys->nelts; i++) {
        if (ngx_ssl_add_certificate(cf, ssl, &cert[i], &key[i])
            != NGX_OK
        ) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_str_t
ngx_ssl_try_load(ngx_str_t *file, ngx_array_t *passwords) {
    ngx_str_t *password;
    ngx_str_t dest;

    password = passwords->elts;

    for (ngx_uint_t i=0; i < passwords->nelts; i++) {
        dest.data = tls_load_file((const char *) file->data,
                                   &dest.len,
                                   (char *) password[i].data);
        if (dest.len > 0) {
            return dest;
        }
    }
    return dest;
}

ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords)
{
    if (cert->len > 0) {
        if (passwords != NGX_CONF_UNSET_PTR && passwords != NULL
            && passwords->nelts != 0
        ) {
            ngx_str_t cert_value = {0}, key_value = {0};

            cert_value = ngx_ssl_try_load(cert, passwords);
            if (cert_value.len == 0) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "failed to open cert %s",
                              cert->data);
                return NGX_ERROR;
            }

            key_value = ngx_ssl_try_load(key, passwords);
            if (key_value.len == 0) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "failed to open key %s",
                              key->data);
                tls_unload_file(cert_value.data, cert_value.len);
                return NGX_ERROR;
            }

            if (tls_config_set_keypair_mem(ssl,
                                           cert_value.data, cert_value.len,
                                           key_value.data, key_value.len)
                == -1
            ) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "unable to set certificate: %s",
                              tls_config_error(ssl));
                tls_unload_file(cert_value.data, cert_value.len);
                tls_unload_file(key_value.data, key_value.len);
                return NGX_ERROR;
            }

        } else {
            if (tls_config_set_keypair_file(ssl,
                                            (const char *) cert->data,
                                            (const char *) key->data)
                == -1
            ) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "unable to set certificate: %s",
                              tls_config_error(ssl));
                return NGX_ERROR;
            }

        }
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_add_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_str_t *key)
{
    if (cert->len > 0) {
        if (tls_config_add_keypair_file(ssl,
                                        (const char *) cert->data,
                                        (const char *) key->data)
            == -1
        ) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unable to add certificate: %s",
                          tls_config_error(ssl));
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords)
{
    ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                  "ssl connection certificate not implemented");
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_array_t *paths)
{
    if (paths != NGX_CONF_UNSET_PTR && paths != NULL && paths->nelts > 0) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "\"ssl_session_ticket_key\" ignored, not supported");
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *ciphers,
    ngx_uint_t prefer_server_ciphers)
{
    if (ciphers->len > 0) {
        if (tls_config_set_ciphers(ssl, (const char *)ciphers->data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "unable to set ciphers: %s",
                          tls_config_error(ssl));
            return NGX_ERROR;
        }
    }

    if (prefer_server_ciphers) {
        tls_config_prefer_ciphers_server(ssl);
    }

    return NGX_OK;
}

ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_int_t depth)
{
    if (cert->len > 0) {
        /* TODO: openssl calls are SSL_CTX_set_client_CA_file but tls doesn't
         * have this should we use tls_config_set_ca_file and just hope that
         * tls_client or tls_server is used later?
         */
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "ssl client certificate not implemented");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_int_t depth)
{
    ngx_str_t conf_prefix;
    conf_prefix = ngx_cycle->conf_prefix;

    if (cert->len > 0) {
        if (ngx_get_full_name(cf->pool, &conf_prefix, cert) != NGX_OK) {
            return NGX_ERROR;
        }

        if (tls_config_set_ca_file(ssl, (const char *) cert->data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unable to set trusted certificate: %s",
                          tls_config_error(ssl));
            return NGX_ERROR;
        }

        if (depth) {
            if (tls_config_set_verify_depth(ssl, depth) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "unable to set certificate verify depth: %s",
                              tls_config_error(ssl));
                return NGX_ERROR;
            }
        }
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *crl)
{
    ngx_str_t conf_prefix;
    conf_prefix = ngx_cycle->conf_prefix;

    if (crl->len > 0) {
        if (ngx_get_full_name(cf->pool, &conf_prefix, crl) != NGX_OK) {
            return NGX_ERROR;
        }

        if (tls_config_set_crl_file(ssl, (const char *) crl->data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "unable to set crl: %s",
                          tls_config_error(ssl));
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify)
{
    ngx_str_t conf_prefix;
    conf_prefix = ngx_cycle->conf_prefix;

    if (file->len > 0) {
        if (ngx_get_full_name(cf->pool, &conf_prefix, file) != NGX_OK) {
            return NGX_ERROR;
        }

        if (tls_config_set_ocsp_staple_file(ssl, (const char *) file->data)
            == -1
        ) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unable to set ocsp staple file: %s",
                          tls_config_error(ssl));
            return NGX_ERROR;
        }
        if (responder->len > 0 || verify != 0) {
            /* TODO: verify stapling file with certs or responder? */
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "ssl stapling verification is not implemented, "
                          "ignoring");
        }
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    if (resolver != NGX_CONF_UNSET_PTR && resolver != NULL) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "ssl stapling resolver not implemented, ignoring");
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone)
{
    if (responder->len > 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ssl ocsp not implemented");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    if (resolver != NGX_CONF_UNSET_PTR && resolver != NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ssl ocsp not implemented");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *file)
{
    if (file->len != 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,\
                      "reading dhparams from file not implemented");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *name)
{
    if (name->len > 0) {
        if (tls_config_set_ecdhecurves(ssl, (const char*)name->data) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unable to set ecdh curves: %s",
                          tls_config_error(ssl));
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_uint_t enable)
{
    if (enable) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ssl early data not implemented");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_array_t *commands)
{
    if (commands != NGX_CONF_UNSET_PTR && commands != NULL
        && commands->nelts > 0
    ) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "ssl conf commands not implemented");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_uint_t enable)
{
    if (enable) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "ssl client session cache not implemented");
        return NGX_ERROR;
    }
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_session_cache(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *sess_ctx,
    ngx_array_t *certificates, ssize_t builtin_session_cache,
    ngx_shm_zone_t *shm_zone, time_t timeout)
{
    switch (builtin_session_cache) {
    case NGX_SSL_NO_SCACHE:
        return NGX_OK;

    case NGX_SSL_NONE_SCACHE:
        /* this is some wild behaviour to lie and make outlook happy
         * (see openssl implementation for more comments)
         * not sure how to support this
         */
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "ignoring \"ssl_session_cache\" value of \"none\", "
                      "only \"builtin\" is implemented");
        return NGX_OK;

    case NGX_SSL_NO_BUILTIN_SCACHE:
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "ignoring \"ssl_session_cache\" value of \"shared:XXX\", "
                      "only \"builtin\" is implemented");
        return NGX_OK;

    case NGX_SSL_DFLT_BUILTIN_SCACHE:
        if (tls_config_set_session_lifetime(ssl, timeout) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unable to set ssl session cache timeout: %s",
                          tls_config_error(ssl));
            return NGX_ERROR;
        }
        if (sess_ctx->len > 0) {
            if (tls_config_set_session_id(ssl, sess_ctx->data, sess_ctx->len) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "unable to set ssl session id: %s",
                              tls_config_error(ssl));
                return NGX_ERROR;
            }
        }
        return NGX_OK;

    default:
        if (builtin_session_cache > 0) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "ignoring \"ssl_session_cache\" value of \"builtin:XXX\", "
                          "only \"builtin\" is implemented");
        }
        return NGX_OK;
    }
}


ngx_int_t
ngx_ssl_handshake(ngx_connection_t *c)
{
    int rv;

    rv = tls_handshake(c->ssl->session_ctx);
    if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "ngx_ssl_handshake() try again");
        return NGX_AGAIN;
    }
    if (rv == -1) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "ngx_ssl_handshake() failed: %s", tls_error(c->ssl->session_ctx));
        return NGX_ERROR;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    c->recv = ngx_ssl_recv;
    c->send = ngx_ssl_send;
    c->recv_chain = ngx_ssl_recv_chain;
    c->send_chain = ngx_ssl_send_chain;

    c->read->ready = 1;
    c->write->ready = 1;

    c->ssl->handshaked = 1;

    return NGX_OK;
}

void
ngx_ssl_connection_close(void *data)
{
    ngx_ssl_connection_t *tc = data;
    tls_close(tc->session_ctx);
    tc->session_ctx = NULL;
}

ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_ssl_connection_flags_t flags)
{
    ngx_ssl_connection_t   *sc;
    ngx_pool_cleanup_t     *cln;

    if (c->ssl == NULL) {

        sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
        if (sc == NULL) {
            return NGX_ERROR;
        }

        if (flags & NGX_SSL_CLIENT) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                          "client ssl not yet implemented");
            return NGX_ERROR;

            /* TODO: client ssl
             * how do I get the servername? I think ngx_http_connection_t has it,
             * but how do I get that?
             */
            if (tls_connect_socket(ssl->ctx, c->fd, "?servername") == -1) {
            }
        } else {
            if (tls_accept_socket(ssl->ctx, &sc->session_ctx, c->fd) == -1) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                              "ngx_ssl_create_connection() tls_accept_socket failed (%s)",
                              tls_error(ssl->ctx));
                return NGX_ERROR;
            }

            cln = ngx_pool_cleanup_add(c->pool, 0);
            cln->handler = ngx_ssl_connection_close;
            cln->data = sc;
        }

        c->ssl = sc;
    }

    return NGX_OK;
}

void
ngx_ssl_free_buffer(ngx_connection_t *c)
{
}

ngx_int_t
ngx_ssl_shutdown(ngx_connection_t *c)
{
    return NGX_OK;
}

ngx_int_t
ngx_ssl_verify_certificate(ngx_connection_t *c, ngx_uint_t verify) {
    if (verify) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "verifying ssl certificate not supported");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_verify_client_sent_certificate(ngx_connection_t *c, ngx_uint_t verify)
{
    if (verify) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "verifying ssl certificate not supported");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name)
{
    ngx_log_error(NGX_LOG_EMERG, c->log, 0, "check ssl host not supported");
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_verify_ocsp(ngx_connection_t *c, ngx_uint_t verify)
{
    if (verify) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "verifying ssl ocsp not supported");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size) {
    ssize_t n = 0, bytes = 0;
    for ( ;; ) {
        n = tls_read(c->ssl->session_ctx, buf, size);
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_read: %d", n);
        c->read->ready = n != TLS_WANT_POLLIN;

        if (n == 0) {
            return bytes;
        } else if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT) {
            return bytes ? bytes : NGX_AGAIN;
        } else if (n < 0) {
            c->read->error = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_read err: %s",
                           tls_error(c->ssl->session_ctx));
            return NGX_ERROR;
        }

        size -= n;
        buf += n;
        bytes += n;

        if (size <= 0) {
            return NGX_AGAIN;
        }
    }
}

ssize_t
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit) {
    ssize_t     n, bytes = 0, size;
    ngx_buf_t  *b;

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
            n = ngx_ssl_recv(c, last, size);
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
ngx_ssl_send(ngx_connection_t *c, u_char *buf, size_t size) {
    ssize_t n = 0, bytes = 0;
    for ( ;; ) {
        n = tls_write(c->ssl->session_ctx, buf, size);
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_write: %d", n);
        c->write->ready = n != TLS_WANT_POLLOUT;

        if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT) {
            return bytes ? bytes : NGX_AGAIN;
        } else if (n < 0) {
            c->write->error = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "tls_write err: %s", tls_error(c->ssl->session_ctx));
            return NGX_ERROR;
        }

        size -= n;
        buf += n;
        bytes += n;

        if (size <= 0) {
            return bytes;
        }
    }
}

ngx_chain_t*
ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit) {
    ssize_t n;
    while (in) {
        if (ngx_buf_special(in->buf)) {
            in = in->next;
            continue;
        }
        n = ngx_ssl_send(c, in->buf->pos, in->buf->last - in->buf->pos);
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

ngx_ssl_session_t *
ngx_ssl_session_create(ngx_ssl_session_t **session, const u_char **buf,
    long len)
{
    return NULL;
}

ngx_int_t
ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    return NGX_ERROR;
}

ngx_ssl_session_t *
ngx_ssl_get_session(ngx_connection_t *c)
{
    return NULL;
}

ngx_ssl_session_t *
ngx_ssl_get0_session(ngx_connection_t *c)
{
    return NULL;
}

int
ngx_ssl_session_buflen(ngx_ssl_session_t *session, void *data)
{
    return 0;
}

void
ngx_ssl_session_free(ngx_ssl_session_t *sesson)
{
    return;
}

ngx_int_t
ngx_ssl_session_cache_init(ngx_shm_zone_t *zone, void *data)
{
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_ocsp_validate(ngx_connection_t *c)
{
    return NGX_ERROR;
}

ngx_int_t
ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s)
{
    return NGX_ERROR;
}

void
ngx_ssl_ocsp_cleanup(ngx_connection_t *c)
{
    return;
}

ngx_int_t
ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    return NGX_ERROR;
}


/* getters */
#define GET_UNSUPPORTED(name) \
    ngx_int_t \
    name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s) \
    { \
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, #name " not supported"); \
        return NGX_ERROR; \
    }
#define GET(name, tls_name) \
    ngx_int_t \
    name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s) \
    { \
        s->data = (u_char *) tls_name(c->ssl->session_ctx); \
        return NGX_OK; \
    }

GET(ngx_ssl_get_protocol, tls_conn_version)
GET(ngx_ssl_get_cipher_name, tls_conn_cipher)
GET_UNSUPPORTED(ngx_ssl_get_ciphers)
GET_UNSUPPORTED(ngx_ssl_get_curve)
GET_UNSUPPORTED(ngx_ssl_get_curves)
GET_UNSUPPORTED(ngx_ssl_get_session_id)
GET_UNSUPPORTED(ngx_ssl_get_session_reused)
GET_UNSUPPORTED(ngx_ssl_get_early_data)
GET(ngx_ssl_get_server_name, tls_conn_servername)
GET(ngx_ssl_get_alpn_protocol, tls_conn_alpn_selected)
GET_UNSUPPORTED(ngx_ssl_get_raw_certificate)
GET_UNSUPPORTED(ngx_ssl_get_certificate)
GET_UNSUPPORTED(ngx_ssl_get_escaped_certificate)
GET(ngx_ssl_get_subject_dn, tls_peer_cert_subject)
GET(ngx_ssl_get_issuer_dn, tls_peer_cert_issuer)
GET_UNSUPPORTED(ngx_ssl_get_subject_dn_legacy)
GET_UNSUPPORTED(ngx_ssl_get_issuer_dn_legacy)
GET_UNSUPPORTED(ngx_ssl_get_serial_number)
GET_UNSUPPORTED(ngx_ssl_get_fingerprint)
GET_UNSUPPORTED(ngx_ssl_get_client_verify)
GET_UNSUPPORTED(ngx_ssl_get_client_v_start)
GET_UNSUPPORTED(ngx_ssl_get_client_v_end)
GET_UNSUPPORTED(ngx_ssl_get_client_v_remain)

#undef GET
#undef GET_UNSUPPORTED

