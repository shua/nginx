
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_TLS_H_INCLUDED_
#define _NGX_EVENT_TLS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_LIBTLS)
#include <tls.h>

#elif (NGX_OPENSSL)

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_OCSP
#include <openssl/ocsp.h>
#endif
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


#if (defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER == 0x20000000L)
#undef OPENSSL_VERSION_NUMBER
#if (LIBRESSL_VERSION_NUMBER >= 0x2080000fL)
#define OPENSSL_VERSION_NUMBER  0x1010000fL
#else
#define OPENSSL_VERSION_NUMBER  0x1000107fL
#endif
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100001L)
#define ngx_ssl_version()       OpenSSL_version(OPENSSL_VERSION)
#else
#define ngx_ssl_version()       SSLeay_version(SSLEAY_VERSION)
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
#define SSL_is_server(s)        (s)->server
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined SSL_get_peer_certificate)
#define SSL_get_peer_certificate(s)  SSL_get1_peer_certificate(s)
#endif

#if (OPENSSL_VERSION_NUMBER < 0x30000000L && !defined ERR_peek_error_data)
#define ERR_peek_error_data(d, f)    ERR_peek_error_line_data(NULL, NULL, d, f)
#endif

#endif


// common const defines
// why can't these just be extern's?
#if (NGX_LIBTLS)
#define NGX_SSL_DEFAULT_CIPHERS "HIGH:!aNULL:!MD5"
#define NGX_SSL_DEFAULT_ECDH_CURVE "default"
#define NGX_SSL_BUFSIZE 16384
#define NGX_SSL_MAX_SESSION_SIZE 0

#elif (NGX_OPENSSL)
#define NGX_SSL_DEFAULT_CIPHERS "HIGH:!aNULL:!MD5"
#define NGX_SSL_DEFAULT_ECDH_CURVE "auto"
#define NGX_SSL_BUFSIZE 16384
#define NGX_SSL_MAX_SESSION_SIZE 0

#endif


typedef enum {
    NGX_SSL_SSLv2   = 1 << 1,
    NGX_SSL_SSLv3   = 1 << 2,
    NGX_SSL_TLSv1   = 1 << 3,
    NGX_SSL_TLSv1_1 = 1 << 4,
    NGX_SSL_TLSv1_2 = 1 << 5,
    NGX_SSL_TLSv1_3 = 1 << 6,
} ngx_ssl_protocol_t;

typedef enum {
    NGX_SSL_BUFFER = 1 << 0,
    NGX_SSL_CLIENT = 1 << 1,
} ngx_ssl_connection_flags_t;

enum {
    NGX_SSL_NO_SCACHE           = -2,
    NGX_SSL_NONE_SCACHE         = -3,
    NGX_SSL_NO_BUILTIN_SCACHE   = -4,
    NGX_SSL_DFLT_BUILTIN_SCACHE = -5,
};


#if (NGX_LIBTLS)
typedef struct tls                ngx_ssl_ctx_t;
typedef struct tls_config         ngx_ssl_conf_t;

// TODO: libtls session
typedef struct {}                 ngx_ssl_session_t;
// TODO: libtls stapling
struct ngx_ssl_ocsp_s {};

#elif (NGX_OPENSSL)
typedef SSL_CTX                   ngx_ssl_ctx_t;
typedef SSL                       ngx_ssl_conn_t;

typedef int (*servername_pt)(ngx_ssl_conn_t *conn, int *ad, void *arg);
typedef SSL_CTX_alpn_select_cb_func  alpn_select_pt;
typedef int (*cert_pt)(ngx_ssl_conn_t *conn, void *arg);

typedef struct {
    ngx_uint_t                    protocols;

    servername_pt                 servername_cb;
    alpn_select_pt                alpn_select_cb;
    void                         *alpn_select_data;
    cert_pt                       certificate_cb;
    void                         *certificate_cb_data;
} ngx_ssl_conf_t;

typedef SSL_SESSION               ngx_ssl_session_t;

#endif


typedef struct {
    ngx_ssl_ctx_t                *ctx;
    ngx_ssl_conf_t               *conf;
    ssize_t                       buffer_size;
} ngx_ssl_t;

typedef struct ngx_ssl_ocsp_s     ngx_ssl_ocsp_t;

typedef struct {
#if (NGX_OPENSSL)
    ngx_ssl_conn_t               *connection;
#endif
    ngx_ssl_ctx_t                *session_ctx;

    ngx_int_t                     last;
    ngx_buf_t                    *buf;
    ssize_t                       buffer_size;

    ngx_ssl_session_t            *session;

    ngx_event_handler_pt          saved_read_handler;
    ngx_event_handler_pt          saved_write_handler;

    ngx_ssl_ocsp_t               *ocsp;

    u_char                        early_buf;

    ngx_connection_handler_pt     handler;
    ngx_connection_handler_pt     save_session;

    unsigned                      handshaked:1;
    unsigned                      handshake_rejected:1;
    unsigned                      renegotiation:1;
    unsigned                      buffer:1;
    unsigned                      sendfile:1;
    unsigned                      no_send_shutdown:1;
    unsigned                      no_wait_shutdown:1;
    unsigned                      shutdown_without_free:1;
    unsigned                      handshake_buffer_set:1;
    unsigned                      try_early_data:1;
    unsigned                      in_early:1;
    unsigned                      in_ocsp:1;
    unsigned                      early_preread:1;
    unsigned                      write_blocked:1;
} ngx_ssl_connection_t;


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_conf_begin(ngx_conf_t *cf, ngx_ssl_t *ssl, void *data);
ngx_int_t ngx_ssl_conf_end(ngx_conf_t *cf, ngx_ssl_t *ssl);

// config commands
ngx_int_t ngx_ssl_protocols(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_ssl_protocol_t protocols);
ngx_int_t ngx_ssl_certificate_values(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *certificate_values, ngx_array_t *key_values,
    ngx_array_t *passwords);
ngx_int_t ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *certs, ngx_array_t *keys, ngx_array_t *passwords);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
ngx_int_t ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *paths);
ngx_int_t ngx_ssl_session_ticket(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_flag_t session_tickets);
ngx_int_t ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
    ngx_uint_t prefer_server_ciphers);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
ngx_int_t ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone);
ngx_int_t ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
ngx_array_t *ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file);
ngx_array_t *ngx_ssl_preserve_passwords(ngx_conf_t *cf,
    ngx_array_t *passwords);
ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file);
ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name);
ngx_int_t ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable);
ngx_int_t ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *commands);
ngx_int_t ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable);
ngx_int_t ngx_ssl_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *sess_ctx, ngx_array_t *certificates,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout);

ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_ssl_connection_flags_t flags);
void      ngx_ssl_free_buffer(ngx_connection_t *c);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);

ngx_int_t ngx_ssl_verify_certificate(ngx_connection_t *c, ngx_uint_t verify);
ngx_int_t ngx_ssl_verify_client_sent_certificate(ngx_connection_t *c, ngx_uint_t verify);
ngx_int_t ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name);
ngx_int_t ngx_ssl_verify_ocsp(ngx_connection_t *c, ngx_uint_t verify);

ssize_t       ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t       ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
ssize_t       ngx_ssl_send(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t*  ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);



// ocsp/stapling
ngx_int_t ngx_ssl_ocsp_validate(ngx_connection_t *c);
ngx_int_t ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s);
void      ngx_ssl_ocsp_cleanup(ngx_connection_t *c);
ngx_int_t ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data);

// session stuff
#if (NGX_LIBTLS)
ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *zone, void *data);
ngx_ssl_session_t *ngx_ssl_session_create(ngx_ssl_session_t **session,
                                          const u_char **buf, long len);
void ngx_ssl_session_free(ngx_ssl_session_t *session);
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c);
ngx_ssl_session_t *ngx_ssl_get0_session(ngx_connection_t *c);
int ngx_ssl_session_buflen(ngx_ssl_session_t *session, void *data);

#elif (NGX_OPENSSL)
#define ngx_ssl_session_create d2i_SSL_SESSION
#define ngx_ssl_session_free SSL_SESSION_free
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c);
ngx_ssl_session_t *ngx_ssl_get0_session(ngx_connection_t *c);
#define ngx_ssl_session_buflen i2d_SSL_SESSION

ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *zone, void *data);
void ngx_ssl_remove_cached_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
#define ngx_ssl_get_connection(ssl_conn)                                      \
    SSL_get_ex_data(ssl_conn, ngx_ssl_connection_index)
#define ngx_ssl_get_server_conf(ssl_ctx)                                      \
    SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_server_conf_index)

#define ngx_ssl_verify_error_optional(n)                                      \
    (n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT                              \
     || n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN                             \
     || n == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY                     \
     || n == X509_V_ERR_CERT_UNTRUSTED                                        \
     || n == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)
#endif


// getters
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

#if (NGX_OPENSSL)
extern int  ngx_ssl_connection_index;
extern int  ngx_ssl_server_conf_index;
extern int  ngx_ssl_session_cache_index;
extern int  ngx_ssl_session_ticket_keys_index;
extern int  ngx_ssl_ocsp_index;
extern int  ngx_ssl_certificate_index;
extern int  ngx_ssl_next_certificate_index;
extern int  ngx_ssl_certificate_name_index;
extern int  ngx_ssl_stapling_index;
#endif

#endif // _NGX_EVENT_TLS_H_INCLUDED_
