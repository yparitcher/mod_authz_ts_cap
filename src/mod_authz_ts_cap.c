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

#include "apr_strings.h"
#include "apr_lib.h"

#include "httpd.h"
#include "http_config.h"
#include "ap_provider.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"
#include "mod_authz_ts_cap.h"
#include "ts_whois.h"

module AP_MODULE_DECLARE_DATA authz_ts_cap_module;


typedef struct {
    const char *tailscale_socket;
    apr_interval_time_t cache_duration;
} ts_srv_config_t;

static void *create_srv_config(apr_pool_t *pool, server_rec *s)
{
    ts_srv_config_t *config = apr_pcalloc(pool, sizeof(*config));

    (void)s;
    return config;
}

static void *merge_srv_config(apr_pool_t *pool, void *basev, void *addv)
{
    ts_srv_config_t *base = (ts_srv_config_t *)basev;
    ts_srv_config_t *add = (ts_srv_config_t *)addv;
    ts_srv_config_t *nsc = apr_pcalloc(pool, sizeof(*nsc));
    nsc->tailscale_socket = add->tailscale_socket? add->tailscale_socket : base->tailscale_socket;

    return nsc;
}

typedef struct {
    const char *tailscale_socket;
    apr_time_t updated;
    apr_array_header_t *caps;
} ts_conn_ctx_t;

static ts_conn_ctx_t *ts_conn_ctx_rget(request_rec *r)
{
    conn_rec *c = r->connection;
    ts_conn_ctx_t *ctx = ap_get_module_config(c->conn_config,
                                              &authz_ts_cap_module);
    ts_srv_config_t *config = ap_get_module_config(r->server->module_config,
                                                   &authz_ts_cap_module);

    ap_assert(config->tailscale_socket);

    if (!ctx) {
        ctx = apr_pcalloc(r->connection->pool, sizeof(*ctx));
        ctx->tailscale_socket = config->tailscale_socket;
        ctx->caps = apr_array_make(r->connection->pool, 1, sizeof(char*));
        ap_set_module_config(c->conn_config, &authz_ts_cap_module, ctx);
    }
    else if (strcmp(config->tailscale_socket, ctx->tailscale_socket)) {
        /* if this request has another tailscale socket configured than
         * the last one on this connection, reset. */
        apr_array_header_t *caps = ctx->caps;
        apr_array_clear(caps);
        memset(&ctx, 0, sizeof(ctx));
        ctx->tailscale_socket = config->tailscale_socket;
        ctx->caps = caps;
    }
    return ctx;
}

static void assure_recent_whois(ts_conn_ctx_t *ctx, request_rec *r)
{
    apr_status_t rv;
    ts_srv_config_t *config = ap_get_module_config(r->server->module_config,
                                                   &authz_ts_cap_module);

    if (ctx->tailscale_socket
        && (!ctx->updated  || (apr_time_now() - ctx->updated) > config->cache_duration)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "get whois from tailscale demon at '%s'", ctx->tailscale_socket);
        rv = ts_whois_get(ctx->caps, r, ctx->tailscale_socket);
        ctx->updated = apr_time_now();
        if (APR_SUCCESS != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "getting tailscale whois");
        }
    }
}

static const char *ts_parse_config(cmd_parms *cmd, const char *require_line,
                                   const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);
    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = expr;
    return NULL;
}

static authz_status ts_cap_check(request_rec *r,
                                               const char *require_args,
                                               const void *parsed_require_args)
{
    ts_conn_ctx_t *ctx;
    const char *require, *err = NULL;
    const char *token;

    (void)require_args;
    ctx = ts_conn_ctx_rget(r);
    if (!ctx->tailscale_socket) {
        goto denied;
    }

    require = ap_expr_str_exec(r, parsed_require_args, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "auth_tailscale authorize: require user: Can't evaluate expression: %s",
                      err);
        goto denied;
    }

    assure_recent_whois(ctx, r);
    if (apr_is_empty_array(ctx->caps)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "does not have any capabilities");
        goto denied;
    }

    token = ap_getword_conf(r->pool, &require);
    char *servername = r->server->server_hostname;
    if (!strcmp(token, "ServerName")) {
        for(int i = 0; i < ctx->caps->nelts; i++){
            const char *cap = ((const char**)ctx->caps->elts)[i];
            if (!strcmp(servername, cap) || !strcmp("*", cap)) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO() "authz_ts_cap authorization successful");
                return AUTHZ_GRANTED;
             }
         }
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01706)
                  "authz_ts_cap authorize, ServerName '%s' did not match", servername);

denied:
    return AUTHZ_DENIED;
}

static const authz_provider authz_ts_cap_provider =
{
    &ts_cap_check,
    &ts_parse_config,
};

static apr_status_t post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv = APR_SUCCESS;
    ts_srv_config_t *config;

    (void)p;
    (void)plog;
    (void)ptemp;
    (void)s;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    for (; s; s = s->next) {
        config = ap_get_module_config(s->module_config, &authz_ts_cap_module);
        if (!config->tailscale_socket) {
            config->tailscale_socket = TAILSCALE_DEF_URL;
        }
        if (!config->cache_duration) {
            config->cache_duration = apr_time_from_sec(1);
        }
    }

    return rv;
}

static const char *cmd_ts_parse_url(cmd_parms *cmd, void *config, const char *url)
{
    ts_srv_config_t *conf = ap_get_module_config(cmd->server->module_config,
                                                 &authz_ts_cap_module);
    apr_uri_t url_parsed;

    (void)config;
    memset(&url_parsed, 0, sizeof(url_parsed));
    if (APR_SUCCESS != apr_uri_parse(cmd->pool, url, &url_parsed)) {
        return "not an url";
    }
    if (url_parsed.scheme && url_parsed.scheme[0]
        && strcmp("file", url_parsed.scheme)) {
        return "not a supported scheme";
    }
    if (url_parsed.hostname  && url_parsed.hostname[0]
        && strcmp("localhost", url_parsed.hostname)) {
        return "hosts other than 'localhost' not supported";
    }
    if (!url_parsed.path || !url_parsed.path[0]) {
        return "path to tailscale unix socket missing";
    }

    ap_assert(conf);
    conf->tailscale_socket = url_parsed.path;
    return NULL;
}

static const char *cmd_ts_cache_duration(cmd_parms *cmd, void *config, const char *val)
{
    ts_srv_config_t *conf = ap_get_module_config(cmd->server->module_config,
                                                 &authz_ts_cap_module);
    (void)config;
    if (ap_timeout_parameter_parse(val, &(conf->cache_duration), "s") != APR_SUCCESS)
        return "AuthTailscaleCacheDuration timeout has wrong format";
    return NULL;
}

static const command_rec authz_ts_cmds[] =
{
    AP_INIT_TAKE1("AuthTailscaleURL", cmd_ts_parse_url, NULL, RSRC_CONF,
                  "URL or path to unix socket of tailscale demon"),
    AP_INIT_TAKE1("AuthTailscaleCacheTimeout", cmd_ts_cache_duration, NULL, RSRC_CONF,
                  "how long to cache tailscale information"),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};

static void register_hooks(apr_pool_t *p)
{
    /* Register authz providers */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ts-cap",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_ts_cap_provider,
                              AP_AUTH_INTERNAL_PER_CONF);

    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authz_ts_cap) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                            /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    create_srv_config,               /* server config */
    merge_srv_config,                /* merge server config */
    authz_ts_cmds,                  /* command apr_table_t */
    register_hooks,                  /* register hooks */
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};
