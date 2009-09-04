#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

typedef struct {
    ngx_msec_t              timeout;
    ngx_msec_t              resolver_timeout;

    ngx_flag_t              so_keepalive;

    ngx_str_t               server_name;

    u_char                 *file_name;
    ngx_int_t               line;

    ngx_array_t             listen;      /* ngx_http_memcachep_listen_t */

    ngx_resolver_t         *resolver;
} ngx_http_memcachedp_srv_conf_t;

typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    ngx_http_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_http_memcachep_listen_t;

typedef struct {
    /* ngx_mail_in_addr_t or ngx_mail_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_http_memcachep_mport_t;

typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_http_memcachep_addr_t */
} ngx_http_memcachep_port_t;

typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_http_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_http_memcachep_addr_t;

typedef struct {
    ngx_http_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
} ngx_http_memcachep_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_http_memcachep_addr_conf_t    conf;
} ngx_http_memcachep_in_addr_t;


static char *ngx_http_memcachep_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_memcachep_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_memcachep_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_memcachep_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
static ngx_int_t ngx_http_memcachep_add_addrs(ngx_conf_t *cf, ngx_http_memcachep_mport_t *mport, ngx_http_memcachep_addr_t *addr);
static ngx_int_t ngx_http_memcachep_add_ports(ngx_conf_t *cf, ngx_array_t *ports, ngx_http_memcachep_listen_t *listen);
static ngx_int_t ngx_http_memcachep_cmp_conf_addrs(const void *one, const void *two);


static ngx_command_t  ngx_http_memcachep_commands[] = {
    { ngx_string("memcached_listen"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_memcachep_listen,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_memcachep_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_memcachep_create_srv_conf,    /* create server configuration */
    ngx_http_memcachep_merge_srv_conf,     /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_memcachep_module = {
    NGX_MODULE_V1,
    &ngx_http_memcachep_module_ctx,        /* module context */
    ngx_http_memcachep_commands,           /* module directives */
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


static void *
ngx_http_memcachep_create_srv_conf(ngx_conf_t *cf)
{   
    ngx_http_memcachedp_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_memcachedp_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     */

    cscf->timeout          = NGX_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive     = NGX_CONF_UNSET;

    cscf->resolver         = NGX_CONF_UNSET_PTR;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line      = cf->conf_file->line;


    if (ngx_array_init(&cscf->listen, cf->pool, 4, sizeof(ngx_http_memcachep_listen_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return cscf;
}

static char *
ngx_http_memcachep_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{   
    ngx_http_memcachedp_srv_conf_t *prev = parent;
    ngx_http_memcachedp_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout, 30000);

    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 1);


    ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name = cf->cycle->hostname;
    }

    ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);

    return NGX_CONF_OK;
}

static char *
ngx_http_memcachep_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{   
    size_t                      len, off;
    in_port_t                   port;
    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    struct sockaddr_in         *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif
    ngx_http_memcachedp_srv_conf_t  *cscf;
    ngx_http_memcachep_listen_t          *ls, *listen;

    ngx_array_t                  ports;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cscf = (ngx_http_memcachedp_srv_conf_t *) ngx_http_conf_get_module_srv_conf(cf, ngx_http_memcachep_module);

    ls = cscf->listen.elts;
    for (i = 0; i < cscf->listen.nelts; i++) {

        sa = (struct sockaddr *) ls[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            off = offsetof(struct sockaddr_in6, sin6_addr);
            len = 16;
            sin6 = (struct sockaddr_in6 *) sa;
            port = sin6->sin6_port;
            break;
#endif  
        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = (struct sockaddr_in *) sa;
            port = sin->sin_port;

            break;
        }

        if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&cscf->listen);

    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_http_memcachep_listen_t));

    ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx; /* srv conf ctx (ngx_http_conf_ctx_t) */

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;
            u_char            buf[NGX_SOCKADDR_STRLEN];

            sa = (struct sockaddr *) ls->sockaddr;

           if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 2;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(sa, buf, NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif  
        }

        if (ngx_strcmp(value[i].data, "ssl") == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_mail_ssl_module");
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }



    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_http_memcachep_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    listen = cscf->listen.elts;

    for (i = 0; i < cscf->listen.nelts; i++) {
        if (ngx_http_memcachep_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }


    return ngx_http_memcachep_optimize_servers(cf, &ports);
}

void
ngx_http_memcachep_close_connection(ngx_connection_t *c)
{   
    ngx_pool_t  *pool;

    c->destroyed = 1;
    pool = c->pool;

    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}

void ngx_http_memcachep_process(ngx_connection_t *c, ngx_str_t uri);

static void
ngx_http_memcachep_send(ngx_connection_t *c, ngx_str_t out)
{
    ssize_t                    n;
    if (out.len == 0) {
       if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_http_memcachep_close_connection(c);
        }
        return;
    }

    n = c->send(c, out.data, out.len);

    if (n > 0) {
        out.len -= n;
        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_memcachep_close_connection(c);
        return;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_http_memcachep_close_connection(c);
        return;
    }
}

static void
ngx_http_memcachep_send_error(ngx_connection_t *c)
{
    ngx_str_t                  msg = ngx_string("ERROR\r\n");
    ngx_http_memcachep_send(c, msg);
}


ngx_int_t
ngx_http_memcachep_parse_command(ngx_connection_t *c, ngx_buf_t *buffer)
{   
    ssize_t                    len, line_len;
    u_char                     ch, *p, *sc, *keystartp, *keyendp;
    ngx_str_t                  uri;
    enum {
        sw_start = 0,
        sw_searchkey,
        sw_fetchkey
    } state;

    state = sw_start;

    len = buffer->last - buffer->pos;

    // 行末までの長さを測る
    line_len = 0;
    keystartp = buffer->pos;
    for (p = buffer->pos; p < buffer->last; p++) {
        ch = *p;

        if (buffer->last - buffer->pos -1 < p - buffer->pos) {
                goto invalid;
        }

        switch (state) {
        case sw_start:
            if (ch == ' ') {
                sc = buffer->start;
                if (p - sc == 3 && sc[0] == 'g' && sc[1] == 'e' && sc[2] == 't') {
                    state = sw_searchkey;
                } else {
                    goto invalid;
                }
            } else if (ch == CR || ch == LF) {
                goto invalid;
            }
            break;
        case sw_searchkey:
            if (ch == CR || ch == LF) {
                goto invalid;
            }
            if (ch != ' ') {
	        keystartp = p;
                state = sw_fetchkey;
            }
            break;
        case sw_fetchkey:
            if (ch == CR || ch == LF || ch == ' ') {
	        keyendp = p;
                goto found;
            }
            break;
        }
    }

    return NGX_AGAIN;

found:

    *keystartp = '/';
    uri.data = keystartp;
    uri.len  = keyendp - keystartp;
    uri.data[uri.len] = '\0';

    ngx_http_memcachep_process(c, uri);

    return NGX_AGAIN;
invalid:
    return NGX_ERROR;
}


void
ngx_http_memcachep_read_line(ngx_event_t *wev)
{
    ngx_int_t                  rc;
    ssize_t                    n;
    ngx_buf_t *buffer;
    ngx_connection_t *c;

    c = wev->data;
    buffer = c->data;

    n = c->recv(c, buffer->last, buffer->end - buffer->last);

    // バッファのサイズ以上の読み込みはソケット閉じる そんなにぉっきぃのはぃらなぃょぉ
    if (n == NGX_ERROR || n == 0) {
        ngx_http_memcachep_close_connection(c);
        return;
    }

    if (n > 0) {
        buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_memcachep_close_connection(c);
            return;
        }
        return;
    }

    rc = ngx_http_memcachep_parse_command(c, buffer);

    // パースに失敗したので ERROR を返す
    if (rc == NGX_ERROR) {
        buffer->last = buffer->pos;
        ngx_http_memcachep_send_error(c);
        return;
    }

    // パース成功して処理終わってる
    if (rc == NGX_AGAIN) {
        buffer->last = buffer->pos;
        return;
    }
}

void
ngx_http_memcachep_init_connection(ngx_connection_t *c)
{

    c->data = ngx_create_temp_buf(c->pool, 1024);

    c->read->handler = ngx_http_memcachep_read_line;

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_memcachep_close_connection(c);
        return;
    }
}

void
ngx_http_memcachep_process(ngx_connection_t *c, ngx_str_t uri)
{
    ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *) c->listening->servers;

    if (1) {
        ngx_http_request_t *r;


        r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
	r->main = r;

        r->pool       = c->pool;

        r->main_conf = ctx->main_conf;
        r->srv_conf  = ctx->srv_conf;
        r->loc_conf  = ctx->loc_conf;

        r->ctx = (void *) ngx_modules;

        r->connection = ngx_pcalloc(c->pool, sizeof(ngx_connection_t));
	r->connection->log = c->log;


	r->connection->read  = ngx_pcalloc(c->pool, sizeof(ngx_event_t));
	r->connection->write = r->connection->read;

        r->connection->write->data    = c;
	r->connection->write->ready   = 1;
	r->connection->write->delayed = 1;

	r->subrequest_in_memory = 1;
	r->buffered = 1;
	r->connection->buffered = 1;
	r->main_filter_need_in_memory = 1;
	r->filter_need_in_memory = 1;

	r->method = NGX_HTTP_GET;

	r->out = ngx_pcalloc(c->pool, sizeof(ngx_chain_t));

        r->variables = ngx_pcalloc(r->pool, 1 * sizeof(ngx_http_variable_value_t));
        if (r->variables == NULL) {
            ngx_http_memcachep_close_connection(c);
            return;
        }

        r->method_name.data = ngx_pcalloc(c->pool, sizeof(u_char *) * (uri.len + 30));
	r->method_name.len  = ngx_sprintf(r->method_name.data, "GET %s HTTP/1.1", uri.data) - r->method_name.data;

        if (ngx_http_internal_redirect(r, &uri, NULL) != NGX_DONE) {
            ngx_http_memcachep_close_connection(c);
            return;
        }

        // ngx_http_postponed_request_t に入って r->postponed の中に response body が入ってる?

        // データが帰って来たのでレスポンス返す
        if (r->postponed && r->postponed->out && r->postponed->out->buf) {
            ngx_str_t    line;
            ngx_str_t    crlf = ngx_string("\r\n");
            ngx_chain_t *cl;

            line.len = (10 + uri.len) * 3;
            line.data = ngx_pnalloc(c->pool, line.len);
            if (line.data == NULL) {
                ngx_http_memcachep_close_connection(c);
                return;
            }
            line.len = ngx_sprintf(line.data, "VALUE %s 0 %d" CRLF, (char *)uri.data, (int)r->headers_out.content_length_n) - line.data;

	    ngx_http_memcachep_send(c, line);

            for (cl = r->postponed->out; cl; cl = cl->next) {
                ssize_t      n, size;
                ngx_str_t buf, buf2;
                buf.data = cl->buf->pos;
                buf.len  = cl->buf->last - cl->buf->pos;
    	   	ngx_http_memcachep_send(c, buf);

                if (!cl->buf->file || !cl->buf->file->fd) {
                    continue;
                }

                // 4096 のサイズずつ転送
                while (1) {
                    size = (r->headers_out.content_length_n - cl->buf->file_last);
                    if (size == 0) {
                        break;
                    }

                    if (size > 4096) {
                        size = 4096;
                    }
                    buf2.data = ngx_pcalloc(c->pool, sizeof(u_char *) * (size + 1));
                    n = ngx_read_file(cl->buf->file, buf2.data, (size_t) size, cl->buf->file_last);
                    if (n != size) {
                        ngx_http_memcachep_close_connection(c);
                        return;
                    }
		    buf2.len = n;
  	   	    ngx_http_memcachep_send(c, buf2);
                    cl->buf->file_last += n;
                }
            }

	    ngx_http_memcachep_send(c, crlf);
	    ngx_http_memcachep_send(c, crlf);
        }
    }
}

static char *
ngx_http_memcachep_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{   
    ngx_uint_t             i, p, last, bind_wildcard;
    ngx_listening_t       *ls;
    ngx_http_memcachep_mport_t       *mport;
    ngx_http_memcachep_port_t  *port;
    ngx_http_memcachep_addr_t  *addr;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {
        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_http_memcachep_addr_t), ngx_http_memcachep_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */
        if (addr[last - 1].wildcard) {
            addr[last - 1].bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {
            if (bind_wildcard && !addr[i].bind) {
                i++;
                continue;
            }

            ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = ngx_http_memcachep_init_connection;
            ls->pool_size = 256;

            /* TODO: error_log directive */
            ls->logp = &cf->cycle->new_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            ls->ipv6only = addr[i].ipv6only;
#endif

            mport = ngx_palloc(cf->pool, sizeof(ngx_http_memcachep_port_t));
            if (mport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = cf->ctx;

            if (i == last - 1) {
                mport->naddrs = last;

            } else {
                mport->naddrs = 1;
                i = 0;
            }

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                if (ngx_http_memcachep_add_addrs6(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (ngx_http_memcachep_add_addrs(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            addr++;
            last--;
        }
    }
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_memcachep_add_addrs(ngx_conf_t *cf, ngx_http_memcachep_mport_t *mport,
    ngx_http_memcachep_addr_t *addr)
{
    u_char              *p;
    size_t               len;
    ngx_uint_t           i;
    ngx_http_memcachep_in_addr_t  *addrs;
    struct sockaddr_in  *sin;
    u_char               buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool,
                               mport->naddrs * sizeof(ngx_http_memcachep_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].ctx;

        len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_memcachep_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_http_memcachep_listen_t *listen)
{
    in_port_t              p;
    ngx_uint_t             i;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_http_memcachep_port_t  *port;
    ngx_http_memcachep_addr_t  *addr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
#endif

    sa = (struct sockaddr *) &listen->sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        p = sin6->sin6_port;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        p = sin->sin_port;
        break;
    }

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(ngx_http_memcachep_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
    addr->socklen = listen->socklen;
    addr->ctx = listen->ctx;
    addr->bind = listen->bind;
    addr->wildcard = listen->wildcard;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    addr->ipv6only = listen->ipv6only;
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_memcachep_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_http_memcachep_addr_t  *first, *second;

    first = (ngx_http_memcachep_addr_t *) one;
    second = (ngx_http_memcachep_addr_t *) two;

    if (first->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (first->bind && !second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->bind && second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}
