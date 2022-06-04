
#ifndef _NGX_EVENT_TLS_H_INCLUDED_
#define _NGX_EVENT_TLS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <tls.h>

#define NGX_SSL_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NGX_SSL_DEFAULT_ECDH_CURVE  "default"

#define NGX_SSL_SSLv2    0x0002
#define NGX_SSL_SSLv3    0x0004
#define NGX_SSL_TLSv1    0x0008
#define NGX_SSL_TLSv1_1  0x0010
#define NGX_SSL_TLSv1_2  0x0020
#define NGX_SSL_TLSv1_3  0x0040


#define NGX_SSL_BUFSIZE  16384

#define NGX_SSL_BUFFER 1
#define NGX_SSL_CLIENT 2

#define NGX_SSL_NO_SCACHE            -2
#define NGX_SSL_NONE_SCACHE          -3
#define NGX_SSL_NO_BUILTIN_SCACHE    -4
#define NGX_SSL_DFLT_BUILTIN_SCACHE  -5

#define NGX_SSL_MAX_SESSION_SIZE      0

typedef struct tls_config ngx_ssl_conf_t;

typedef struct {
    struct tls  *ctx;
    ngx_log_t   *log;
} ngx_ssl_t;

typedef struct {
    struct tls  *ctx;

    void       (*handler)(ngx_connection_t*);
    void       (*save_session)(ngx_connection_t*);

    long         verify_error;

    unsigned     handshaked:1;
    unsigned     no_send_shutdown:1;
    unsigned     no_wait_shutdown:1;
    unsigned     shutdown_without_free:1;
    unsigned     sendfile:1;
} ngx_ssl_connection_t;

typedef struct {
} ngx_ssl_session_t;

ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_conf_create(ngx_conf_t *cf, ngx_ssl_conf_t **conf, void *data);
void ngx_ssl_conf_free(ngx_ssl_conf_t *conf);
ngx_int_t ngx_ssl_create(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_ssl_conf_t *conf);
void ngx_ssl_cleanup_ctx(void *data);

ngx_int_t ngx_ssl_protocols(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_uint_t protocols);

ngx_int_t ngx_ssl_certificate_values(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_array_t *certificate_values, ngx_array_t *key_values,
    ngx_array_t *passwords);
ngx_int_t ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_array_t *certs, ngx_array_t *keys, ngx_array_t *passwords);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
ngx_int_t ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_array_t *paths);

ngx_int_t ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *ciphers,
    ngx_uint_t prefer_server_ciphers);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *crl);
ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
ngx_int_t ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone);
ngx_int_t ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
ngx_array_t *ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file);
ngx_array_t *ngx_ssl_preserve_passwords(ngx_conf_t *cf,
    ngx_array_t *passwords);
ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *file);
ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_conf_t *ssl, ngx_str_t *name);
ngx_int_t ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_uint_t enable);
ngx_int_t ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_array_t *commands);

ngx_int_t ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_uint_t enable);
ngx_int_t ngx_ssl_session_cache(ngx_conf_t *cf, ngx_ssl_conf_t *ssl,
    ngx_str_t *sess_ctx, ngx_array_t *certificates,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout);

ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t use);
void ngx_ssl_free_buffer(ngx_connection_t *c);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);

ngx_int_t ngx_ssl_verify_certificate(ngx_connection_t *c, ngx_uint_t verify);
ngx_int_t ngx_ssl_verify_client_sent_certificate(ngx_connection_t *c, ngx_uint_t verify);
ngx_int_t ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name);
ngx_int_t ngx_ssl_verify_ocsp(ngx_connection_t *c, ngx_uint_t verify);

ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
ssize_t ngx_ssl_send(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t* ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);

ngx_ssl_session_t *ngx_ssl_session_create(ngx_ssl_session_t **session,
    const u_char **buf, long len);
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c);
ngx_ssl_session_t *ngx_ssl_get0_session(ngx_connection_t *c);
int ngx_ssl_session_buflen(ngx_ssl_session_t *session, void *data);
void ngx_ssl_free_session(ngx_ssl_session_t *sesson);

ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *zone, void *data);
ngx_int_t ngx_ssl_ocsp_validate(ngx_connection_t *c);
ngx_int_t ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s);
void ngx_ssl_ocsp_cleanup(ngx_connection_t *c);
ngx_int_t ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data);

ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_ciphers(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_curve(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_curves(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_early_data(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_alpn_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_escaped_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_v_start(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_v_end(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_v_remain(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);

#endif // _NGX_EVENT_TLS_H_INCLUDED_
