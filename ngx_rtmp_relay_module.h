
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_RELAY_H_INCLUDED_
#define _NGX_RTMP_RELAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


typedef struct {
    ngx_url_t                       url;
    ngx_str_t                       app;
    ngx_str_t                       name;
    ngx_str_t                       tc_url;
    ngx_str_t                       page_url;
    ngx_str_t                       swf_url;
    ngx_str_t                       flash_ver;
    ngx_str_t                       play_path;
    ngx_int_t                       live;
    ngx_int_t                       start;
    ngx_int_t                       stop;

#if (NGX_RTMP_SSL)

    ngx_int_t                       is_rtmps;
    ngx_ssl_t                      *ssl;
    ngx_str_t                       ssl_name;
    ngx_flag_t                      ssl_server_name;
    ngx_flag_t                      ssl_verify;

#endif

    void                           *tag;     /* usually module reference */
    void                           *data;    /* module-specific data */
    ngx_uint_t                      counter; /* mutable connection counter */
} ngx_rtmp_relay_target_t;


typedef struct ngx_rtmp_relay_ctx_s ngx_rtmp_relay_ctx_t;

struct ngx_rtmp_relay_ctx_s {
    ngx_str_t                       name;
    ngx_str_t                       proto;
    ngx_str_t                       url;
    ngx_log_t                       log;
    ngx_rtmp_session_t             *session;
    ngx_rtmp_relay_ctx_t           *publish;
    ngx_rtmp_relay_ctx_t           *play;
    ngx_rtmp_relay_ctx_t           *next;

    ngx_str_t                       app;
    ngx_str_t                       tc_url;
    ngx_str_t                       page_url;
    ngx_str_t                       swf_url;
    ngx_str_t                       flash_ver;
    ngx_str_t                       play_path;
    ngx_int_t                       live;
    ngx_int_t                       start;
    ngx_int_t                       stop;

#if (NGX_RTMP_SSL)

    ngx_str_t                       ssl_name;
    ngx_flag_t                      ssl_server_name;
    ngx_flag_t                      ssl_verify;

#endif

    ngx_event_t                     push_evt;
    ngx_event_t                    *static_evt;
    void                           *tag;
    void                           *data;
};


typedef struct {
    ngx_array_t                 pulls;         /* ngx_rtmp_relay_target_t * */
    ngx_array_t                 pushes;        /* ngx_rtmp_relay_target_t * */
    ngx_array_t                 static_pulls;  /* ngx_rtmp_relay_target_t * */
    ngx_array_t                 static_events; /* ngx_event_t * */
    ngx_log_t                  *log;
    ngx_uint_t                  nbuckets;
    ngx_msec_t                  buflen;
    ngx_flag_t                  session_relay;
    ngx_msec_t                  push_reconnect;
    ngx_msec_t                  pull_reconnect;
    ngx_rtmp_relay_ctx_t        **ctx;

#if (NGX_RTMP_SSL)

    ngx_uint_t                  ssl_protocols;
    ngx_str_t                   ssl_ciphers;
    ngx_flag_t                  ssl_server_name;
    ngx_flag_t                  ssl_verify;
    ngx_uint_t                  ssl_verify_depth;
    ngx_str_t                   ssl_trusted_certificate;
    ngx_str_t                   ssl_crl;

#endif

} ngx_rtmp_relay_app_conf_t;


extern ngx_module_t                 ngx_rtmp_relay_module;


ngx_int_t ngx_rtmp_relay_pull(ngx_rtmp_session_t *s, ngx_str_t *name,
                              ngx_rtmp_relay_target_t *target);
ngx_int_t ngx_rtmp_relay_push(ngx_rtmp_session_t *s, ngx_str_t *name,
                              ngx_rtmp_relay_target_t *target);

#if (NGX_RTMP_SSL)

ngx_int_t ngx_rtmp_relay_configure_ssl(ngx_conf_t *cf,
                                       ngx_rtmp_relay_app_conf_t *racf,
                                       ngx_rtmp_relay_target_t *target);

#endif


#endif /* _NGX_RTMP_RELAY_H_INCLUDED_ */
