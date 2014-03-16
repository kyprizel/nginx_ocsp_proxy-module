/*
    v0.06

    Copyright (C) 2013-2014 Eldar Zaitov (eldar@kyprizel.net).
    All rights reserved.
    This module is licenced under the terms of BSD license.

*/
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <time.h>
#include <openssl/ocsp.h>

#define ocsp_request_content_type "application/ocsp-request"
#define ocsp_request_content_type_len (sizeof(ocsp_request_content_type) - 1)

#define DDEBUG 0

/* response valid lag buffer time */
#define TIME_BUF 300

typedef struct {
    ngx_flag_t                  enable;
    time_t                      max_cache_time;
} ngx_http_ocsp_proxy_conf_t;


typedef struct {
    OCSP_CERTID     *cid;
    ngx_str_t       serial;
    ngx_str_t       ocsp_request;
    unsigned        valid;
    time_t          delta;
    unsigned        done:1;
    unsigned        waiting_more_body:1;
    unsigned        skip_caching;
    unsigned        state;
} ngx_http_ocsp_proxy_ctx_t;


static ngx_int_t ngx_http_ocsp_proxy_handler(ngx_http_request_t *r);
static void ngx_http_ocsp_proxy_handle_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_ocsp_proxy_handle_response(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_int_t
copy_ocsp_certid(ngx_http_request_t *r, OCSP_CERTID *dst, OCSP_CERTID *src);
static ngx_int_t
process_ocsp_request(ngx_http_request_t *r, u_char *buf, size_t len);
static ngx_int_t
ngx_http_ocsp_proxy_process_post_body(ngx_http_request_t *r);

static ngx_int_t ngx_http_ocsp_proxy_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ocsp_proxy_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_ocsp_request_get_serial_variable(ngx_http_request_t *r,
                    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ocsp_request_get_skip_caching_variable(ngx_http_request_t *r,
                    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ocsp_request_get_delta_variable(ngx_http_request_t *r,
                    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_ocsp_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_http_ocsp_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_str_t  ngx_http_ocsp_serial = ngx_string("ocsp_serial");
static ngx_str_t  ngx_http_ocsp_skip_caching = ngx_string("ocsp_skip_cache");
static ngx_str_t  ngx_http_ocsp_delta = ngx_string("ocsp_response_cache_time");
static ngx_str_t  ngx_http_ocsp_request = ngx_string("ocsp_request");

static ngx_command_t  ngx_http_ocsp_proxy_filter_commands[] = {
    { ngx_string("ocsp_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ocsp_proxy_conf_t, enable),
      NULL },


    { ngx_string("ocsp_cache_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ocsp_proxy_conf_t, max_cache_time),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ocsp_proxy_filter_module_ctx = {
    ngx_http_ocsp_proxy_add_variables,         /* preconfiguration */
    ngx_http_ocsp_proxy_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ocsp_proxy_create_conf,           /* create location configration */
    ngx_http_ocsp_proxy_merge_conf             /* merge location configration */
};


ngx_module_t  ngx_http_ocsp_proxy_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_ocsp_proxy_filter_module_ctx,    /* module context */
    ngx_http_ocsp_proxy_filter_commands,       /* module directives */
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


static ngx_int_t
ngx_http_ocsp_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_ocsp_proxy_conf_t      *conf;
    ngx_http_ocsp_proxy_ctx_t       *ctx;
    u_char                          *p, *last, *start, *dst, *src;
    ngx_str_t                        value;
    ngx_int_t                        rc = NGX_HTTP_BAD_REQUEST;
    ngx_str_t                        b64req;
    ngx_str_t                        rreq;
    size_t                           b64len, len;

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_ocsp_proxy_filter_module);
    if (!conf->enable || r->internal) {
        return NGX_DECLINED;
    }

    if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_GET) {
        return rc;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx != NULL) {
        if (ctx->done) {
            return NGX_DECLINED;
        }
        /* wtf? */
        return NGX_DECLINED;
    }

    /*
        ctx->state = 0
    */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ocsp_proxy_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ocsp_proxy_filter_module);

    if (r->method == NGX_HTTP_GET) {
        /* Some browsers using MS CryptoAPI (IE, Chromium, Opera) use GET */
        p = start = &r->unparsed_uri.data[0];
        last = r->unparsed_uri.data + r->unparsed_uri.len;

        while (p < last) {
            if (*p++ == '/') {
                start = p;
            }
        }

        b64len = last - start;
        if (b64len <= 0) {
            return rc;
        }

        src = start;

        b64req.data = (u_char *) ngx_pcalloc(r->pool, b64len);
        if (b64req.data == NULL) {
            return NGX_ERROR;
        }

        dst = b64req.data;
        ngx_unescape_uri(&dst, &src, b64len, NGX_UNESCAPE_URI);
        b64req.len = b64len;

        len = ngx_base64_decoded_length(b64len);
        if (len <= 0) {
            return rc;
        }

        rreq.data = (u_char *) ngx_pcalloc(r->pool, len);
        if (rreq.data == NULL) {
            return NGX_ERROR;
        }

        if (ngx_decode_base64(&rreq, &b64req) != NGX_OK) {
            return rc;
        }

        ctx->ocsp_request.data = (u_char *) ngx_pcalloc(r->pool, rreq.len);
        ngx_memcpy(ctx->ocsp_request.data, rreq.data, rreq.len);
        ctx->ocsp_request.len = rreq.len;

        ctx->state = 1;

        /* parse OCSP request here */
        if (process_ocsp_request(r, rreq.data, rreq.len) != NGX_OK) {
            return rc;
        }
        ctx->done = 1;
        return NGX_DECLINED;
    }


    if (r->headers_in.content_type == NULL
        || r->headers_in.content_type->value.data == NULL)
    {
        return rc;
    }

    value = r->headers_in.content_type->value;

    if (value.len < ocsp_request_content_type_len
        || ngx_strncasecmp(value.data, (u_char *) ocsp_request_content_type,
                           ocsp_request_content_type_len) != 0)
    {
        return rc;
    }


    rc = ngx_http_read_client_request_body(r, ngx_http_ocsp_proxy_handle_body);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        ctx->waiting_more_body = 1;
        return NGX_DONE;
    }

    return NGX_DECLINED;
}


static void
ngx_http_ocsp_proxy_handle_body(ngx_http_request_t *r)
{
    ngx_http_ocsp_proxy_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);

    r->read_event_handler = ngx_http_request_empty_handler;

    ctx->done = 1;

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;

        ngx_http_core_run_phases(r);
    }
}

static ngx_int_t
ngx_http_ocsp_request_get_skip_caching_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ocsp_proxy_ctx_t   *ctx;
    ngx_http_ocsp_proxy_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_request_get_skip_caching_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_ocsp_proxy_filter_module);
    if (!conf->enable) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

#if DDEBUG

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx->skip_caching: %d, ctx->valid: %d", ctx->skip_caching, ctx->valid);

#endif

    switch (ctx->state) {
    case 1:
        v->data = (u_char *) ngx_pcalloc(r->pool, 1);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        if (ctx->skip_caching == 1) {
            ngx_memcpy(v->data, "1", 1);
        } else {
            ngx_memcpy(v->data, "0", 1);
        }
        v->len = 1;
        break;
    case 2:
        v->data = (u_char *) ngx_pcalloc(r->pool, 1);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        if (ctx->valid == 1 && ctx->skip_caching == 0) {
            ngx_memcpy(v->data, "0", 1);
        } else {
            ngx_memcpy(v->data, "1", 1);
        }
        v->len = 1;
        break;
    default:
        /* 
            wtf? unknown state?
            invalid OCSP request
        */
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ocsp_request_get_delta_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ocsp_proxy_ctx_t   *ctx;
    ngx_http_ocsp_proxy_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_request_get_delta_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_ocsp_proxy_filter_module);
    if (!conf->enable) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    if (ctx->skip_caching == 1 || ctx->delta == 0) {
        ngx_memcpy(v->data, "0", 1);
        v->len = 1;
        goto complete;
    }

    if (ctx->delta > conf->max_cache_time) {
        v->len = ngx_sprintf(v->data, "%T", conf->max_cache_time) - v->data;
    } else {
        v->len = ngx_sprintf(v->data, "%T", ctx->delta) - v->data;
    }

complete:

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
copy_ocsp_certid(ngx_http_request_t *r, OCSP_CERTID *dst, OCSP_CERTID *src)
{
    u_char              *data1;
    char                *data2;

    /* required */
    if (!src->hashAlgorithm || !src->hashAlgorithm->algorithm
        || src->hashAlgorithm->algorithm->length <= 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OCSP no hash algo specified");
        return NGX_ERROR;
    }

    /* required */
    if (!src->issuerNameHash || src->issuerNameHash->length <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OCSP no issuer name hash specified");
        return NGX_ERROR;
    }

    if (!src->serialNumber || src->serialNumber->length <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OCSP no serial specified");
        return NGX_ERROR;
    }

    dst->hashAlgorithm = (X509_ALGOR *) ngx_pcalloc(r->pool, sizeof(X509_ALGOR));
    if (dst->hashAlgorithm == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->hashAlgorithm, dst->hashAlgorithm, sizeof(ASN1_INTEGER));

    dst->hashAlgorithm->algorithm = (ASN1_OBJECT *) ngx_pcalloc(r->pool, sizeof(ASN1_OBJECT));
    if (dst->hashAlgorithm->algorithm == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->hashAlgorithm->algorithm, src->hashAlgorithm->algorithm, sizeof(ASN1_OBJECT));

    data1 = (u_char *) ngx_pcalloc(r->pool, src->hashAlgorithm->algorithm->length);
    if (data1 == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(data1, src->hashAlgorithm->algorithm->data, src->hashAlgorithm->algorithm->length);
    dst->hashAlgorithm->algorithm->data = (const u_char *)data1;

    if (src->hashAlgorithm->algorithm->sn && ngx_strlen(src->hashAlgorithm->algorithm->sn) > 0) {
        data2 = (char *) ngx_pcalloc(r->pool, ngx_strlen(src->hashAlgorithm->algorithm->sn) + 1);
        if (data2 == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(data2, src->hashAlgorithm->algorithm->sn, ngx_strlen(src->hashAlgorithm->algorithm->sn));
        dst->hashAlgorithm->algorithm->sn = (const char *)data2;
    }

    if (src->hashAlgorithm->algorithm->ln && ngx_strlen(src->hashAlgorithm->algorithm->ln) > 0) {
        data2 = (char *) ngx_pcalloc(r->pool, ngx_strlen(src->hashAlgorithm->algorithm->ln) + 1);
        if (data2 == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(data2, src->hashAlgorithm->algorithm->ln, ngx_strlen(src->hashAlgorithm->algorithm->ln));
        dst->hashAlgorithm->algorithm->ln = (const char *)data2;
    }

    dst->issuerNameHash = (ASN1_OCTET_STRING *) ngx_pcalloc(r->pool, sizeof(ASN1_OCTET_STRING));
    if (dst->issuerNameHash == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->issuerNameHash, src->issuerNameHash, sizeof(ASN1_OCTET_STRING));

    if (src->issuerNameHash->length > 0) {
        dst->issuerNameHash->data = (u_char *) ngx_pcalloc(r->pool, src->issuerNameHash->length);
        if (dst->issuerNameHash->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(dst->issuerNameHash->data, src->issuerNameHash->data, src->issuerNameHash->length);
    }

    dst->issuerKeyHash = (ASN1_OCTET_STRING *) ngx_pcalloc(r->pool, sizeof(ASN1_OCTET_STRING)); 
    if (dst->issuerKeyHash == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->issuerKeyHash, src->issuerKeyHash, sizeof(ASN1_OCTET_STRING));

    if (src->issuerKeyHash->length > 0) {
        dst->issuerKeyHash->data = (u_char *) ngx_pcalloc(r->pool, src->issuerKeyHash->length);
        if (dst->issuerKeyHash->data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(dst->issuerKeyHash->data, src->issuerKeyHash->data, src->issuerKeyHash->length);
    }

    dst->serialNumber = (ASN1_INTEGER *) ngx_pcalloc(r->pool, sizeof(ASN1_INTEGER));
    if (dst->serialNumber == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->serialNumber, src->serialNumber, sizeof(ASN1_INTEGER));

    dst->serialNumber->data = (u_char *) ngx_pcalloc(r->pool, src->serialNumber->length);
    if (dst->serialNumber->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->serialNumber->data, src->serialNumber->data, src->serialNumber->length);

    return NGX_OK;
}

static ngx_int_t
process_ocsp_request(ngx_http_request_t *r, u_char *buf, size_t len)
{
#if OPENSSL_VERSION_NUMBER >= 0x0090707fL
    const
#endif
    u_char                      *d;
    ngx_http_ocsp_proxy_ctx_t   *ctx;
    OCSP_REQUEST                *ocsp = NULL;
    OCSP_REQINFO                *inf = NULL;
    OCSP_ONEREQ                 *one = NULL;
    OCSP_CERTID                 *cid = NULL;
    BIGNUM                      *bnser = NULL;
    char                        *serial = NULL;
    size_t                      slen;
    int                         n;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "process_ocsp_request");

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->serial.len > 0) {
        /* request was already processed */
        return NGX_OK;
    }

    d = buf;

    ocsp = d2i_OCSP_REQUEST(NULL, &d, len);
    if (ocsp == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "d2i_OCSP_REQUEST() failed");
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "process_ocsp_request 1");

    if (ocsp->tbsRequest == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP request format error");
        goto error;
    }

    /* Check if there is service locator ext in the request */
    n = OCSP_REQUEST_get_ext_by_NID(ocsp, NID_id_pkix_OCSP_serviceLocator, -1);
    if (n >= 0) {
        /* If there is service locator extension - we should not cache response on this request */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "got OCSP request with service locator extension");
        ctx->skip_caching = 1;
    }

    inf = ocsp->tbsRequest;

    /* we process only one request */
    if (sk_OCSP_ONEREQ_num(inf->requestList) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP request format error, != 1");
        goto error;
    }

    one = sk_OCSP_ONEREQ_value(inf->requestList, 0);
    if (one == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP request format error, no valid requests found");
        goto error;
    }

    cid = one->reqCert;
    if (cid == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP request format error, no valid certificate id");
        goto error;
    }

    ctx->cid = (OCSP_CERTID *) ngx_pcalloc(r->pool, sizeof(OCSP_CERTID));
    if (ctx->cid == NULL) {
        goto error;
    }

    if (copy_ocsp_certid(r, ctx->cid, cid) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Error while copying OCSP_CERTID");
        goto error;
    }

    bnser = ASN1_INTEGER_to_BN(cid->serialNumber, NULL);
    if (bnser == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP request format error, serial bignum err");
        goto error;
    }

    slen = BN_num_bytes(bnser) * 2;
    if (slen <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP request format error, serial len <= 0");
        goto error;
    }

    serial = BN_bn2hex(bnser);
    if (serial == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP request error, BN2hex alloc failed");
        goto error;
    }

    ctx->serial.data = (u_char *) ngx_pcalloc(r->pool, slen);
    if (ctx->serial.data == NULL) {
        goto error;
    }
    ngx_memcpy(ctx->serial.data, serial, slen);
    ctx->serial.len = slen;

    BN_free(bnser);
    OPENSSL_free(serial);
    OCSP_REQUEST_free(ocsp);

    return NGX_OK;

error:

    if (ctx->ocsp_request.len > 0) {
        /* will nginx free the buf? */
        ctx->ocsp_request.len = 0;
    }

    if (bnser) {
        BN_free(bnser);
    }
    if (serial) {
        OPENSSL_free(serial);
    }
    if (ocsp) {
        OCSP_REQUEST_free(ocsp);
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_ocsp_proxy_process_post_body(ngx_http_request_t *r) {
    ngx_http_ocsp_proxy_ctx_t   *ctx;
    ngx_buf_t                   *b;
    u_char                      *p, *buf, *last;
    size_t                      len;
    ngx_chain_t                 *cl;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (r->method != NGX_HTTP_POST || ctx->state != 0) {
        return NGX_ERROR;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_ERROR;
    }

    ctx->state = 1;

    if (r->request_body->bufs->next != NULL) {
        /* more than one buffer...we should copy the data out... */
        len = 0;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            b = cl->buf;

            if (b->in_file) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "OCSP proxy: in-file buffer found. aborted. "
                            "Too big OCSP request found.");
                return NGX_ERROR;
            }

            len += b->last - b->pos;
        }

        if (len == 0) {
            return NGX_ERROR;
        }

        buf = ngx_palloc(r->pool, len);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        p = buf;
        last = p + len;

        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }
    } else {
        b = r->request_body->bufs->buf;
        if (ngx_buf_size(b) == 0) {
            return NGX_ERROR;
        }

        buf = b->pos;
        last = b->last;
    }

    len = last-buf;

    ctx->ocsp_request.data = (u_char *) ngx_pcalloc(r->pool, len);
    if (ctx->ocsp_request.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->ocsp_request.data, buf, len);
    ctx->ocsp_request.len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ocsp_request_get_b64encoded_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ocsp_proxy_ctx_t   *ctx;
    ngx_http_ocsp_proxy_conf_t  *conf;
    ngx_str_t                   rreq;
    size_t                      b64len;
#if 0
    uintptr_t                   escape;
    u_char                      *p;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_request_get_b64encoded_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_ocsp_proxy_filter_module);
    if (!conf->enable) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->ocsp_request.len > 0) {
        goto complete;
    }

    /* process POST body only once */
    if (ctx->state == 0) {
        if (ngx_http_ocsp_proxy_process_post_body(r) != NGX_OK) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    if (!ctx->cid || ctx->serial.len == 0) {
        if (process_ocsp_request(r, ctx->ocsp_request.data, ctx->ocsp_request.len) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "OCSP proxy: request processing error");
            v->not_found = 1;
            return NGX_OK;
        }
    }

complete:

    b64len = ngx_base64_encoded_length(ctx->ocsp_request.len);
    if (b64len <= 0 || b64len < ctx->ocsp_request.len) {
        return NGX_ERROR;
    }

    rreq.data = (u_char *) ngx_pcalloc(r->pool, b64len);
    if (rreq.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&rreq, &ctx->ocsp_request);
#if 0
    escape = 2 * ngx_escape_uri(NULL, &rreq, rreq.len, NGX_ESCAPE_URI_COMPONENT);

    b64len = rreq.len + escape;
#endif
    v->data = (u_char *) ngx_pcalloc(r->pool, b64len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
#if 0
    if (escape == 0) {
        p = (u_char *) ngx_cpymem(v->data, rreq.data, rreq.len);
    } else {
        p = (u_char *) ngx_escape_uri(v->data, rreq.data, rreq.len, NGX_ESCAPE_URI_COMPONENT);
    }
    v->len = p - v->data;
#else
    ngx_memcpy(v->data, rreq.data, rreq.len);
    v->len = rreq.len;
#endif

    return NGX_OK;
}



static ngx_int_t
ngx_http_ocsp_request_get_serial_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ocsp_proxy_ctx_t   *ctx;
    ngx_http_ocsp_proxy_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_request_get_serial_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_ocsp_proxy_filter_module);
    if (!conf->enable) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* was serial already set in this ctx? */
    if (ctx->serial.len > 0) {
        goto complete;
    }

    /* process POST body only once */
    if (ctx->state == 0) {
        if (ngx_http_ocsp_proxy_process_post_body(r) != NGX_OK) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    if (process_ocsp_request(r, ctx->ocsp_request.data, ctx->ocsp_request.len) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "OCSP proxy: request processing error");
        v->not_found = 1;
        return NGX_OK;
    }

complete:

    v->data = (u_char *) ngx_pcalloc(r->pool, ctx->serial.len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_memcpy(v->data, ctx->serial.data, ctx->serial.len);
    v->len = ctx->serial.len;

    return NGX_OK;
}

/* XXX: make it nice! */
static time_t
ASN1_GetTimeT(ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;

    memset(&t, 0, sizeof(t));

    if (time->length < 14) {
        goto complete;
    }

    if (time->type == V_ASN1_UTCTIME) {  /* two digit year */
        t.tm_year = (str[0] - '0') * 10 + (str[1] - '0');
        if (t.tm_year < 70)
        t.tm_year += 100;
    } else if (time->type == V_ASN1_GENERALIZEDTIME) { /* four digit year */
        t.tm_year = (str[0] - '0') * 1000 + (str[1] - '0') * 100 + (str[2] - '0') * 10 + (str[3] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon = ((str[4] - '0') * 10 + (str[5] - '0')) - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[6] - '0') * 10 + (str[7] - '0');
    t.tm_hour = (str[8] - '0') * 10 + (str[9] - '0');
    t.tm_min  = (str[10] - '0') * 10 + (str[11] - '0');
    t.tm_sec  = (str[12] - '0') * 10 + (str[13] - '0');

complete:
    return mktime(&t);
}

static ngx_int_t
ngx_http_ocsp_proxy_handle_response(ngx_http_request_t *r, ngx_chain_t *in)
{

#if OPENSSL_VERSION_NUMBER >= 0x0090707fL
    const
#endif
    u_char                      *d;
    ngx_http_ocsp_proxy_conf_t  *conf;
    ngx_http_ocsp_proxy_ctx_t   *ctx;
    u_char                      *p, *buf, *last;
    size_t                      len;
    ngx_chain_t                 *cl;
    ngx_buf_t                   *b;
    int                         n, delta;
    OCSP_RESPONSE               *ocsp = NULL;
    OCSP_BASICRESP              *basic = NULL;
    ASN1_GENERALIZEDTIME        *thisupdate = NULL;
    ASN1_GENERALIZEDTIME        *nextupdate = NULL;
    time_t                      now, t_tmp, timedelta;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_proxy_handle_response");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_ocsp_proxy_filter_module);
    if (!conf->enable) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in == NULL || r->header_only) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_proxy_handle_response: no body or header only");
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ocsp_proxy_filter_module);
    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_proxy_handle_response ctx not set");
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->cid == NULL) {
        /* wtf? */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_ocsp_proxy_handle_response invalid request");
        return ngx_http_next_body_filter(r, in);
    }

    if (in->next != NULL) {
        len = 0;
        for (cl = in; cl; cl = cl->next) {
            b = cl->buf;
            len += b->last - b->pos;
        }

        if (len == 0) {
            return NGX_ERROR;
        }

        buf = ngx_palloc(r->pool, len);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        p = buf;
        last = p + len;

        for (cl = in; cl; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }
    } else {
        b = in->buf;
        if (ngx_buf_size(b) == 0) {
            return ngx_http_next_body_filter(r, in);
        }

        buf = b->pos;
        last = b->last;
    }

    len = last-buf;
    d = buf;

    ctx->state = 2;

    ocsp = d2i_OCSP_RESPONSE(NULL, &d, len);
    if (ocsp == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "d2i_OCSP_RESPONSE() failed");
        goto error;
    }

    n = OCSP_response_status(ocsp);
    if (n != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        ctx->valid = 0;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP response not successful (%d: %s)",
                      n, OCSP_response_status_str(n));
        goto error;
    }


    basic = OCSP_response_get1_basic(ocsp);
    if (basic == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP_response_get1_basic() failed");
        goto error;
    }

    /* Check for nonce in response */
    n = OCSP_BASICRESP_get_ext_by_NID(basic, NID_id_pkix_OCSP_Nonce, -1);
    if (n >= 0) {
        /* If there is nonce - we should not cache the response */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "got OCSP response with nonce");

        ctx->skip_caching = 1;
    }

    if (OCSP_resp_find_status(basic, ctx->cid, &n, NULL, NULL,
                              &thisupdate, &nextupdate)
        != 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "certificate status not found in the OCSP response");
        goto error;
    }


    if (n != V_OCSP_CERTSTATUS_GOOD) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "certificate status \"%s\" in the OCSP response",
                      OCSP_cert_status_str(n));
        goto error;
    }


    if (OCSP_check_validity(thisupdate, nextupdate, TIME_BUF, -1) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OCSP_check_validity() failed");
        goto error;
    }

    if (nextupdate) {
        now = ngx_time();
        t_tmp = ASN1_GetTimeT(nextupdate);
        delta = difftime(now, t_tmp);

        /* store response until nextupdate - TIME_BUF */
        if (delta > 0 || (delta + TIME_BUF) >= 0) {
            /* wtf? */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OCSP response exp datetime in the past or format error");
            goto error;
        }

        timedelta = (time_t) (delta * -1);
        if (timedelta > conf->max_cache_time) {
            timedelta = conf->max_cache_time;
        }
        ctx->delta = timedelta;
    } else {
        ctx->delta = conf->max_cache_time;
    }

#if DDEBUG
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "delta: %d, serial: %v", ctx->delta, &ctx->serial);
#endif

    ctx->valid = 1;

    OCSP_BASICRESP_free(basic);

    OCSP_RESPONSE_free(ocsp);

    return ngx_http_next_body_filter(r, in);

error:

    if (basic) {
        OCSP_BASICRESP_free(basic);
    }

    if (ocsp) {
        OCSP_RESPONSE_free(ocsp);
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t
ngx_http_ocsp_proxy_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_ocsp_serial, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_ocsp_request_get_serial_variable;

    var = ngx_http_add_variable(cf, &ngx_http_ocsp_skip_caching, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_ocsp_request_get_skip_caching_variable;

    var = ngx_http_add_variable(cf, &ngx_http_ocsp_delta, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_ocsp_request_get_delta_variable;

    var = ngx_http_add_variable(cf, &ngx_http_ocsp_request, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_ocsp_request_get_b64encoded_variable;

    return NGX_OK;
}

static void *
ngx_http_ocsp_proxy_create_conf(ngx_conf_t *cf)
{
    ngx_http_ocsp_proxy_conf_t  *conf;

    conf = (ngx_http_ocsp_proxy_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_ocsp_proxy_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     */

    conf->enable = NGX_CONF_UNSET;
    conf->max_cache_time = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_ocsp_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ocsp_proxy_conf_t *prev = parent;
    ngx_http_ocsp_proxy_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    /* default max_cache_time = 3600 * 24 */
    ngx_conf_merge_value(conf->max_cache_time,
                              prev->max_cache_time, 86400);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ocsp_proxy_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (NULL == h) {
        return NGX_ERROR;
    }
    *h = ngx_http_ocsp_proxy_handler;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ocsp_proxy_handle_response;

    return NGX_OK;
}
