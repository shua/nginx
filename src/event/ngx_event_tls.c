
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/* ngx_event_tls.c contains some function definitions that are not dependent
 * on the ssl implementation you link with.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_SSL_PASSWORD_BUFFER_SIZE  4096

static void ngx_ssl_passwords_cleanup(void *data);


ngx_array_t *
ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file)
{
    u_char              *p, *last, *end;
    size_t               len;
    ssize_t              n;
    ngx_fd_t             fd;
    ngx_str_t           *pwd;
    ngx_array_t         *passwords;
    ngx_pool_cleanup_t  *cln;
    u_char               buf[NGX_SSL_PASSWORD_BUFFER_SIZE];

    if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
        return NULL;
    }

    passwords = ngx_array_create(cf->temp_pool, 4, sizeof(ngx_str_t));
    if (passwords == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->temp_pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ssl_passwords_cleanup;
    cln->data = passwords;

    fd = ngx_open_file(file->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%s\" failed", file->data);
        return NULL;
    }

    len = 0;
    last = buf;

    do {
        n = ngx_read_fd(fd, last, NGX_SSL_PASSWORD_BUFFER_SIZE - len);

        if (n == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_read_fd_n " \"%s\" failed", file->data);
            passwords = NULL;
            goto cleanup;
        }

        end = last + n;

        if (len && n == 0) {
            *end++ = LF;
        }

        p = buf;

        for ( ;; ) {
            last = ngx_strlchr(last, end, LF);

            if (last == NULL) {
                break;
            }

            len = last++ - p;

            if (len && p[len - 1] == CR) {
                len--;
            }

            if (len) {
                pwd = ngx_array_push(passwords);
                if (pwd == NULL) {
                    passwords = NULL;
                    goto cleanup;
                }

                pwd->len = len;
                pwd->data = ngx_pnalloc(cf->temp_pool, len);

                if (pwd->data == NULL) {
                    passwords->nelts--;
                    passwords = NULL;
                    goto cleanup;
                }

                ngx_memcpy(pwd->data, p, len);
            }

            p = last;
        }

        len = end - p;

        if (len == NGX_SSL_PASSWORD_BUFFER_SIZE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "too long line in \"%s\"", file->data);
            passwords = NULL;
            goto cleanup;
        }

        ngx_memmove(buf, p, len);
        last = buf + len;

    } while (n != 0);

    if (passwords->nelts == 0) {
        pwd = ngx_array_push(passwords);
        if (pwd == NULL) {
            passwords = NULL;
            goto cleanup;
        }

        ngx_memzero(pwd, sizeof(ngx_str_t));
    }

cleanup:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%s\" failed", file->data);
    }

    ngx_explicit_memzero(buf, NGX_SSL_PASSWORD_BUFFER_SIZE);

    return passwords;
}


ngx_array_t *
ngx_ssl_preserve_passwords(ngx_conf_t *cf, ngx_array_t *passwords)
{
    ngx_str_t           *opwd, *pwd;
    ngx_uint_t           i;
    ngx_array_t         *pwds;
    ngx_pool_cleanup_t  *cln;
    static ngx_array_t   empty_passwords;

    if (passwords == NULL) {

        /*
         * If there are no passwords, an empty array is used
         * to make sure OpenSSL's default password callback
         * won't block on reading from stdin.
         */

        return &empty_passwords;
    }

    /*
     * Passwords are normally allocated from the temporary pool
     * and cleared after parsing configuration.  To be used at
     * runtime they have to be copied to the configuration pool.
     */

    pwds = ngx_array_create(cf->pool, passwords->nelts, sizeof(ngx_str_t));
    if (pwds == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ssl_passwords_cleanup;
    cln->data = pwds;

    opwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {

        pwd = ngx_array_push(pwds);
        if (pwd == NULL) {
            return NULL;
        }

        pwd->len = opwd[i].len;
        pwd->data = ngx_pnalloc(cf->pool, pwd->len);

        if (pwd->data == NULL) {
            pwds->nelts--;
            return NULL;
        }

        ngx_memcpy(pwd->data, opwd[i].data, opwd[i].len);
    }

    return pwds;
}


static void
ngx_ssl_passwords_cleanup(void *data)
{
    ngx_array_t *passwords = data;

    ngx_str_t   *pwd;
    ngx_uint_t   i;

    pwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {
        ngx_explicit_memzero(pwd[i].data, pwd[i].len);
    }
}

