/***************************************************************************
 *                                  _   _ ____  _
 * Copyright (C) 2022, Stefan Eissing, <stefan@eissing.org>, et al.
 * Copyright (C) 2024, Y Paritcher <y@paritcher.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <curl/curl.h>

/* jansson thinks everyone compiles with the platform's cc in its fullest capabilities
 * when undefining their INLINEs, we get static, unused functions, arg
 */
#if defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunreachable-code"
#elif defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

#include <jansson_config.h>
#undef  JSON_INLINE
#define JSON_INLINE
#include <jansson.h>

#include <apr_strings.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include "mod_authz_ts_cap.h"
#include "ts_whois.h"


static long timeout_msec(apr_time_t timeout)
{
    long ms = (long)apr_time_as_msec(timeout);
    return ms? ms : (timeout? 1 : 0);
}

static apr_status_t curl_status(unsigned int curl_code)
{
    switch (curl_code) {
        case CURLE_OK:                   return APR_SUCCESS;
        case CURLE_UNSUPPORTED_PROTOCOL: return APR_ENOTIMPL;
        case CURLE_NOT_BUILT_IN:         return APR_ENOTIMPL;
        case CURLE_URL_MALFORMAT:        return APR_EINVAL;
        case CURLE_COULDNT_RESOLVE_PROXY:return APR_ECONNREFUSED;
        case CURLE_COULDNT_RESOLVE_HOST: return APR_ECONNREFUSED;
        case CURLE_COULDNT_CONNECT:      return APR_ECONNREFUSED;
        case CURLE_REMOTE_ACCESS_DENIED: return APR_EACCES;
        case CURLE_OUT_OF_MEMORY:        return APR_ENOMEM;
        case CURLE_OPERATION_TIMEDOUT:   return APR_TIMEUP;
        case CURLE_SSL_CONNECT_ERROR:    return APR_ECONNABORTED;
        case CURLE_AGAIN:                return APR_EAGAIN;
        default:                         return APR_EGENERAL;
    }
}

static const char *parse_ct(apr_pool_t *pool, const char *cth)
{
    const char *p;

    if (!cth) return NULL;
    for( p = cth; *p && *p != ' ' && *p != ';'; ++p)
        ;
    return apr_pstrndup(pool, cth, (apr_size_t)(p - cth));
}

static size_t json_load_cb(void *data, size_t max_len, void *baton)
{
    apr_bucket_brigade *body = baton;
    size_t blen, read_len = 0;
    const char *bdata;
    char *dest = data;
    apr_bucket *b;
    apr_status_t rv;

    while (body && !APR_BRIGADE_EMPTY(body) && max_len > 0) {
        b = APR_BRIGADE_FIRST(body);
        if (APR_BUCKET_IS_METADATA(b)) {
            if (APR_BUCKET_IS_EOS(b)) {
                body = NULL;
            }
        }
        else {
            rv = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
            if (rv == APR_SUCCESS) {
                if (blen > max_len) {
                    apr_bucket_split(b, max_len);
                    blen = max_len;
                }
                memcpy(dest, bdata, blen);
                read_len += blen;
                max_len -= blen;
                dest += blen;
            }
            else {
                body = NULL;
                if (!APR_STATUS_IS_EOF(rv)) {
                    /* everything beside EOF is an error */
                    read_len = (size_t)-1;
                }
            }
        }
        APR_BUCKET_REMOVE(b);
        apr_bucket_delete(b);
    }

    return read_len;
}

static json_t *json_readb(request_rec *r, apr_bucket_brigade *bb)
{
    json_error_t error;
    json_t *j;

    j = json_load_callback(json_load_cb, bb, 0, &error);
    if (!j) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "error parsing JSON(line %d, col %d): %s",
                      error.line, error.column, error.text);
    }
    return j;
}

typedef struct {
    apr_pool_t *pool;
    apr_table_t *headers;
    apr_off_t body_limit;
    apr_bucket_brigade *body;
} ts_whois_ctx_t;

static size_t header_cb(void *buffer, size_t elen, size_t nmemb, void *baton)
{
    ts_whois_ctx_t *whois_ctx = baton;
    size_t len, clen = elen * nmemb;
    const char *name = NULL, *value = "", *b = buffer;
    apr_size_t i;

    len = (clen && b[clen-1] == '\n')? clen-1 : clen;
    len = (len && b[len-1] == '\r')? len-1 : len;
    for (i = 0; i < len; ++i) {
        if (b[i] == ':') {
            name = apr_pstrndup(whois_ctx->pool, b, i);
            ++i;
            while (i < len && b[i] == ' ') {
                ++i;
            }
            if (i < len) {
                value = apr_pstrndup(whois_ctx->pool, b+i, len - i);
            }
            break;
        }
    }

    if (name != NULL) {
        apr_table_add(whois_ctx->headers, name, value);
    }
    return clen;
}

static size_t resp_data_cb(void *data, size_t len, size_t nmemb, void *baton)
{
    ts_whois_ctx_t *whois_ctx = baton;
    size_t blen = len * nmemb;
    apr_status_t rv;

    if (whois_ctx->body) {
        if (whois_ctx->body_limit) {
            apr_off_t body_len = 0;
            apr_brigade_length(whois_ctx->body, 0, &body_len);
            if (body_len + (apr_off_t)blen > whois_ctx->body_limit) {
                return 0; /* signal curl failure */
            }
        }
        rv = apr_brigade_write(whois_ctx->body, NULL, NULL, (const char *)data, blen);
        if (rv != APR_SUCCESS) {
            /* returning anything != blen will make CURL fail this */
            return 0;
        }
    }
    return blen;
}

static const char *get_jstring(json_t *jstring, request_rec *r)
{
    if (jstring && json_is_string(jstring)) {
        const char *cap =  json_string_value(jstring);
        if (strlen(cap) > TS_CAP_MAXLEN) {
             ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "cap too long: '%s'", cap);
        } else {
        	return cap;
        }
    }
    return NULL;
}

apr_status_t ts_whois_get(apr_array_header_t *caps, request_rec *r, const char *uds_path)
{
    CURL *curl;
    CURLcode curle;
    const char *url;
    apr_status_t rv = APR_SUCCESS;
    apr_pool_t *ptemp = NULL;
    ts_whois_ctx_t whois_ctx;
    const char *ctype, *s;
    long l;
    json_t *json = NULL;

    ap_assert(uds_path);
    apr_array_clear(caps);

    curl = curl_easy_init();
    if (!curl) {
        rv = APR_EGENERAL;
        goto leave;
    }
    memset(&whois_ctx, 0, sizeof(whois_ctx));

    rv = apr_pool_create(&ptemp, r->pool);
    if (APR_SUCCESS != rv) {
        ptemp = NULL;
        goto leave;
    }
    apr_pool_tag(ptemp, "ts_whois_temp");

    whois_ctx.pool = ptemp;
    whois_ctx.headers = apr_table_make(whois_ctx.pool, 10);
    whois_ctx.body_limit = 1024*1024;
    whois_ctx.body = apr_brigade_create(whois_ctx.pool, r->connection->bucket_alloc);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &whois_ctx);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_data_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &whois_ctx);

    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_msec(apr_time_from_sec(5)));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_msec(apr_time_from_sec(1)));

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, uds_path);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, MOD_AUTHZ_TS_CAP_VERSION);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "tailscale addr family: %d", r->connection->client_addr->family);
    if (r->connection->client_addr->family == 6) {
        url = apr_psprintf(whois_ctx.pool, "http://local-tailscaled.sock/localapi/v0/whois?addr=%s:%d",
                       r->useragent_ip, r->useragent_addr->port);
    } else {
        url = apr_psprintf(whois_ctx.pool, "http://local-tailscaled.sock/localapi/v0/whois?addr=%s:%d",
                       r->useragent_ip, r->useragent_addr->port);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);

    curle = curl_easy_perform(curl);
    rv = curl_status(curle);
    if (APR_SUCCESS != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "update whois failed(%d): %s",
                      curle, curl_easy_strerror(curle));
        goto leave;
    }
    rv = curl_status(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &l));
    if (APR_SUCCESS != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "unable to get HTTP response status(%d): %s",
                      curle, curl_easy_strerror(curle));
        goto leave;
    }

    switch(l) {
        case 200:
            break;
        case 404:
            goto leave;
        default:
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "unexpected HTTP response status: %ld", l);
            rv = APR_EGENERAL;
            goto leave;
    }

    /* got a 200 response, should have a JSON body */
    ctype = parse_ct(whois_ctx.pool, apr_table_get(whois_ctx.headers, "content-type"));
    if (!ctype) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "response has no content-type");
        rv = APR_EGENERAL;
        goto leave;
    }
    s = ctype + strlen(ctype) +1;
    if (strcmp(s - sizeof("/json"), "/json")
        && strcmp(s - sizeof("+json"), "+json")) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "response content-type does not look like json: '%s'", ctype);
        rv = APR_EGENERAL;
        goto leave;
    }

    json = json_readb(r, whois_ctx.body);
    if (!json) {
        rv = APR_EINVAL;
        goto leave;
    }
    if (json_is_object(json)) {
        json_t *capmap;
        capmap = json_object_get(json, "CapMap");
        if (capmap && json_is_object(capmap)) {
            json_t *servername;
            servername = json_object_get(capmap, "httpd.apache.org/ts-cap/ServerName");
	        if (servername && json_is_array(servername)) {
	             size_t servername_len = json_array_size(servername);
	             if (servername_len > 0){
	             size_t index;
				json_t *value;
				json_array_foreach(servername, index, value) {
	                     const char *s = get_jstring(value, r);
	                     if (s != NULL) {
	                          *(const char**)apr_array_push(caps)  = apr_pstrdup(r->connection->pool, s);
	                     }
	                 }
	             }
             }
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "tailscale capabilities: %s", apr_array_pstrcat(r->connection->pool, caps, ','));

leave:
    if (curl) curl_easy_cleanup(curl);
    if (json) json_decref(json);
    if (ptemp) apr_pool_destroy(ptemp);
    return rv;
}

