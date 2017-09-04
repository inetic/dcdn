#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sodium.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "log.h"
#include "utp.h"
#include "http.h"
#include "base64.h"
#include "timer.h"
#include "network.h"
#include "constants.h"
#include "bev_splice.h"
#include "hash_table.h"
#include "utp_bufferevent.h"


typedef struct {
    in_addr_t ip;
    port_t port;
} PACKED address;

typedef struct {
    address addr;
    uint32_t last_connect;
    uint32_t last_connect_attempt;
} peer;

typedef struct {
    bool failed:1;
    uint32_t last_connect_attempt;
    bool never_connected:1;
    uint8_t salt;
    peer *peer;
} PACKED peer_sort;

#define CACHE_PATH "cache/"
#define CACHE_NAME CACHE_PATH "cache.XXXXXXXX"
#define CACHE_HEADERS_NAME CACHE_NAME ".headers"

typedef struct {
    network *n;
    evhttp_request *direct_req;
    evhttp_request *proxy_req;
    evhttp_request *proxy_head_req;
    evhttp_request *server_req;
    void (*evhttp_handle_request)(struct evhttp_request *, void *);
    crypto_generichash_state content_state;
    char cache_name[sizeof(CACHE_NAME)];
    int cache_file;
    peer *peer;
    bool dht_lookup_running:1;
    bool dht_lookup_cancelled:1;
    bool injector:1;
    bool dont_free:1;
} proxy_request;

network *g_n;
peer *injectors;
uint injectors_len;
peer *injector_proxies;
uint injector_proxies_len;
peer *all_peers;
uint all_peers_len;
time_t injector_reachable;
bool try_direct = true;


bool memeq(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) == 0;
}

int mkpath(char *file_path)
{
    for (char *p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(file_path, 0755) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                return -1;
            }
        }
        *p = '/';
    }
    return 0;
}

void add_addresses(peer **peers, uint *ppeers_len, const byte *addrs, uint num_addrs)
{
    uint peers_len = *ppeers_len;
    for (uint i = 0; i < num_addrs; i++) {
        for (uint j = 0; j < peers_len; j++) {
            if (memeq(&addrs[sizeof(address) * i], (const uint8_t *)&(*peers)[j].addr, sizeof(address))) {
                return;
            }
        }
        peers_len++;
        *ppeers_len = peers_len;
        *peers = realloc(*peers, peers_len * sizeof(peer));
        bzero(&(*peers)[peers_len-1], sizeof(peer));
        memcpy(&(*peers)[peers_len-1].addr, &addrs[sizeof(address) * i], sizeof(address));
        address *a = &(*peers)[peers_len-1].addr;
        debug("new injector%s %s:%d\n", *peers == injectors ? "" : " proxy",
            inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
    }
}

void update_injector_proxy_swarm(network *n)
{
    add_nodes_callblock c = ^(const byte *peers, uint num_peers) {
        if (peers) {
            add_addresses(&injector_proxies, &injector_proxies_len, peers, num_peers);
        }
    };
    if (injector_reachable) {
        dht_get_peers(n->dht, injector_proxy_swarm, c);
    } else {
        dht_announce(n->dht, injector_proxy_swarm, c);
    }
}

void remove_server_req_cb(proxy_request *p)
{
    p->server_req->cb = p->evhttp_handle_request;
    p->server_req->cb_arg = p->n->http;
    evhttp_request_set_error_cb(p->server_req, NULL);
}

void proxy_cache_delete(proxy_request *p)
{
    close(p->cache_file);
    p->cache_file = -1;
    unlink(p->cache_name);
}

void proxy_request_cleanup(proxy_request *p)
{
    debug("df:%d preq:%p phr:%p dr:%p\n", p->dont_free, p->proxy_req, p->proxy_head_req, p->direct_req);
    p->dht_lookup_cancelled = true;
    if (p->dont_free || p->proxy_req || p->proxy_head_req || p->direct_req || p->dht_lookup_running) {
        return;
    }
    if (p->server_req) {
        if (!p->server_req->response_code) {
            evhttp_send_error(p->server_req, 502, "Bad Gateway");
        } else {
            evhttp_send_reply_end(p->server_req);
        }
        remove_server_req_cb(p);
        p->server_req = NULL;
    }
    proxy_cache_delete(p);
    free(p);
}

void proxy_cancel_proxy(proxy_request *p)
{
    if (p->proxy_req) {
        evhttp_cancel_request(p->proxy_req);
        p->proxy_req = NULL;
    }
    if (p->proxy_head_req) {
        evhttp_cancel_request(p->proxy_head_req);
        p->proxy_head_req = NULL;
    }
}

void direct_chunked_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = evhttp_request_get_input_buffer(req);
    //debug("p:%p direct_chunked_cb length:%zu\n", p, evbuffer_get_length(input));
    evhttp_send_reply_chunk(p->server_req, input);
}

int direct_header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p direct_header_cb %d %s\n", p, evhttp_request_get_response_code(req), evhttp_request_get_response_code_line(req));
    proxy_cancel_proxy(p);
    copy_all_headers(req, p->server_req);
    evhttp_send_reply_start(p->server_req, evhttp_request_get_response_code(req), evhttp_request_get_response_code_line(req));
    evhttp_request_set_chunked_cb(req, direct_chunked_cb);
    return 0;
}

void direct_error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p direct_error_cb %d\n", p, error);
    p->direct_req = NULL;
    proxy_request_cleanup(p);
}

void direct_request_done_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p direct_request_done_cb %p\n", p, req);
    if (!req) {
        return;
    }
    debug("p:%p direct server_request_done_cb con:%p %s\n", p, req->evcon, evhttp_request_get_uri(p->server_req));
    p->direct_req = NULL;
    proxy_request_cleanup(p);
}

void proxy_chunked_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = evhttp_request_get_input_buffer(req);
    //debug("p:%p proxy_chunked_cb length:%zu\n", p, evbuffer_get_length(input));
    struct evbuffer_ptr ptr;
    struct evbuffer_iovec v;
    evbuffer_ptr_set(input, &ptr, 0, EVBUFFER_PTR_SET);
    while (evbuffer_peek(input, -1, &ptr, &v, 1) > 0) {
        crypto_generichash_update(&p->content_state, v.iov_base, v.iov_len);
        ssize_t w = write(p->cache_file, v.iov_base, v.iov_len);
        if (w != (ssize_t)v.iov_len) {
            fprintf(stderr, "p:%p cache write failed %d (%s)\n", p, errno, strerror(errno));
            proxy_cache_delete(p);
            proxy_cancel_proxy(p);
            proxy_request_cleanup(p);
            break;
        }
        if (evbuffer_ptr_set(input, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
}

int proxy_header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_header_cb %d %s\n", p, evhttp_request_get_response_code(req), evhttp_request_get_response_code_line(req));

    // not the first moment of connection, but does indicate protocol support
    p->peer->last_connect = time(NULL);

    int code = evhttp_request_get_response_code(req);
    switch(evhttp_request_get_response_code(req)) {
    case HTTP_MOVEPERM:
    case HTTP_MOVETEMP: {
        // redirects are not allowed
        return -1;
    }
    case HTTP_OK:
    case HTTP_NOCONTENT:
        break;
    default:
        return -1;
    }

    if (req == p->proxy_head_req) {
        return 0;
    }

    if (p->proxy_head_req) {
        const char *sign = evhttp_find_header(evhttp_request_get_input_headers(req), "X-Sign");
        if (sign) {
            evhttp_cancel_request(p->proxy_head_req);
            p->proxy_head_req = NULL;
        }
    }

    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);
    hash_headers(evhttp_request_get_input_headers(req), &p->content_state);

    mkpath(p->cache_name);
    p->cache_file = mkstemp(p->cache_name);
    debug("start cache:%s\n", p->cache_name);

    evhttp_request_set_chunked_cb(req, proxy_chunked_cb);
    return 0;
}

void proxy_error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_error_cb %d\n", p, error);
    if (error != EVREQ_HTTP_REQUEST_CANCEL && p->injector) {
        injector_reachable = 0;
    }
    p->proxy_req = NULL;
    proxy_request_cleanup(p);
}

void proxy_head_error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_head_error_cb %d\n", p, error);
    p->proxy_head_req = NULL;
    proxy_request_cleanup(p);
}

bool verify_signature(proxy_request *p, const char *sign)
{
    const char *uri = evhttp_request_get_uri(p->server_req);

    debug("verifying sig for %s %s\n", uri, sign);

    if (strlen(sign) != BASE64_LENGTH(sizeof(content_sig))) {
        fprintf(stderr, "Incorrect length! %zu != %zu\n", strlen(sign), sizeof(content_sig));
        return false;
    }

    size_t out_len = 0;
    uint8_t *raw_sig = base64_decode(sign, strlen(sign), &out_len);
    if (out_len != sizeof(content_sig)) {
        fprintf(stderr, "Incorrect length! %zu != %zu\n", out_len, sizeof(content_sig));
        free(raw_sig);
        return false;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES] = injector_pk;

    content_sig *sig = (content_sig*)raw_sig;
    if (crypto_sign_verify_detached(sig->signature, (uint8_t*)sig->sign, sizeof(content_sig) - sizeof(sig->signature), pk)) {
        fprintf(stderr, "Incorrect signature!\n");
        free(raw_sig);
        return false;
    }

    uint8_t content_hash[crypto_generichash_BYTES];
    crypto_generichash_final(&p->content_state, content_hash, sizeof(content_hash));

    if (memcmp(content_hash, sig->content_hash, sizeof(content_hash))) {
        fprintf(stderr, "Incorrect hash!\n");
        free(raw_sig);
        return false;
    }

    free(raw_sig);
    return true;
}

bool addr_is_localhost(const sockaddr *sa, socklen_t salen)
{
    if (sa->sa_family == AF_INET) {
        const sockaddr_in *sin = (sockaddr_in *)sa;
        uint8_t *ip = (uint8_t*)&sin->sin_addr;
        return ip[0] == 127;
    }
    return false;
}

bool evcon_is_local_browser(evhttp_connection *evcon)
{
    int fd = bufferevent_getfd(evhttp_connection_get_bufferevent(evcon));
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    getsockname(fd, (sockaddr *)&ss, &len);
    // AF_LOCAL is from socketpair(), which means utp
    if (ss.ss_family == AF_LOCAL) {
        return false;
    }
    return addr_is_localhost((sockaddr *)&ss, len);
}

void copy_response_headers(evhttp_request *from, evhttp_request *to)
{
    const char *response_header_whitelist[] = {"Content-Length", "Content-Type"};
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(from, to, response_header_whitelist[i]);
    }
    if (!evcon_is_local_browser(evhttp_request_get_connection(to))) {
        copy_header(from, to, "Content-Location");
        copy_header(from, to, "X-Sign");
    }
}

void proxy_request_done_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_request_done_cb req:%p\n", p, req);
    if (!req) {
        return;
    }
    if (!req->evcon) {
        // connection failed
        if (p->injector) {
            injector_reachable = 0;
        }
    }
    if (p->server_req) {
        const char *sign = evhttp_find_header(evhttp_request_get_input_headers(req), "X-Sign");
        if (!sign) {
            if (req == p->proxy_req) {
                debug("no signature; waiting for HEAD request.\n");
            } else {
                fprintf(stderr, "no signature!\n");
            }
        } else {
            assert(req == p->proxy_req || !p->proxy_req);
            if (verify_signature(p, sign)) {
                if (p->injector) {
                    injector_reachable = time(NULL);
                    update_injector_proxy_swarm(p->n);
                }
                char headers_name[] = CACHE_HEADERS_NAME;
                int headers_file = mkstemps(headers_name, sizeof(headers_name) - sizeof(p->cache_name));
                evkeyvalq *in = evhttp_request_get_input_headers(req);
                const char *headers[] = hashed_headers;
                for (int i = -1; i < (int)lenof(headers); i++) {
                    const char *key = i == -1 ? "X-Sign" : headers[i];
                    const char *value = evhttp_find_header(in, key);
                    if (!value) {
                        continue;
                    }
                    char buf[1024];
                    int s = snprintf(buf, sizeof(buf), "%s: %s\r\n", key, value);
                    if (s >= (ssize_t)sizeof(buf)) {
                        close(headers_file);
                        unlink(headers_name);
                        break;
                    }
                    ssize_t w = write(headers_file, buf, s);
                    if (s != w) {
                        close(headers_file);
                        unlink(headers_name);
                        break;
                    }
                }
                write(headers_file, "\r\n", 2);
                close(headers_file);
                close(p->cache_file);
                p->cache_file = -1;
                const char *content_location = evhttp_find_header(in, "Content-Location");
                char *uri = evhttp_encode_uri(content_location);
                char cache_path[2048];
                char cache_headers_path[2048];
                snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, uri);
                snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
                free(uri);
                debug("store cache:%s headers:%s\n", cache_path, cache_headers_path);
                rename(p->cache_name, cache_path);
                rename(headers_name, cache_headers_path);
                int fd = open(cache_path, O_RDONLY);
                off_t length = lseek(fd, 0, SEEK_END);
                evbuffer *content = evbuffer_new();
                evbuffer_add_file(content, fd, 0, length);
                debug("responding with %d %s %u\n", evhttp_request_get_response_code(req),
                    evhttp_request_get_response_code_line(req), length);
                if (p->direct_req) {
                    evhttp_cancel_request(p->direct_req);
                    p->direct_req = NULL;
                }
                copy_response_headers(req, p->server_req);
                evhttp_send_reply(p->server_req, evhttp_request_get_response_code(req),
                    evhttp_request_get_response_code_line(req), content);
                if (content) {
                    evbuffer_free(content);
                }
                remove_server_req_cb(p);
                p->server_req = NULL;
                join_url_swarm(p->n, content_location);
            }
        }
    }
    if (req == p->proxy_head_req) {
        p->proxy_head_req = NULL;
    } else {
        p->proxy_req = NULL;
    }
    proxy_request_cleanup(p);
}

evhttp_connection* evhttp_utp_create(network *n, const sockaddr *to, socklen_t tolen)
{
    utp_socket *s = utp_create_socket(n->utp);
    int fd = utp_socket_create_fd(n->evbase, s);
    utp_connect(s, to, tolen);
    bufferevent *bev = bufferevent_socket_new(n->evbase, fd, BEV_OPT_CLOSE_ON_FREE);
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    getnameinfo(to, tolen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
    return evhttp_connection_base_bufferevent_new(n->evbase, n->evdns, bev, host, atoi(serv));
}

int peer_sort_cmp(const peer_sort *pa, const peer_sort *pb)
{
    return memcmp(pa, pb, sizeof(peer_sort));
}

peer* select_peer(peer *peers, uint peers_len)
{
    peer_sort best = {.peer = NULL};
    for (size_t i = 0; i < peers_len; i++) {
        peer *p = &peers[i];
        peer_sort c;
        c.failed = p->last_connect < p->last_connect_attempt;
        c.last_connect_attempt = p->last_connect_attempt;
        c.never_connected = !p->last_connect;
        c.salt = rand() & 0xFF;
        c.peer = p;
        address *a = &p->addr;
        if (!i || peer_sort_cmp(&c, &best) < 0) {
            best = c;
        }
    }
    return best.peer;
}

evhttp_connection* peer_connection(network *n, peer *peers, uint peers_len, peer **pp)
{
    peer *p = select_peer(peers, peers_len);
    if (!p) {
        return NULL;
    }
    *pp = p;
    p->last_connect_attempt = time(NULL);
    address *a = &p->addr;
    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
    debug("selected %s:%d\n", inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
    return evhttp_utp_create(n, (sockaddr*)&sin, sizeof(sin));
}

evhttp_connection* injector_connection(network *n, peer **p)
{
    return peer_connection(n, injectors, injectors_len, p);
}

evhttp_connection* injector_proxy_connection(network *n, peer **p)
{
    return peer_connection(n, injector_proxies, injector_proxies_len, p);
}

void direct_submit_request(proxy_request *p, const evhttp_uri *uri)
{
    assert(!p->direct_req);
    p->direct_req = evhttp_request_new(direct_request_done_cb, p);

    copy_all_headers(p->server_req, p->direct_req);

    evhttp_request_set_header_cb(p->direct_req, direct_header_cb);
    evhttp_request_set_error_cb(p->direct_req, direct_error_cb);

    char request_uri[2048];
    const char *q = evhttp_uri_get_query(uri);
    snprintf(request_uri, sizeof(request_uri), "%s%s%s", evhttp_uri_get_path(uri), q?"?":"", q?q:"");
    evhttp_connection *evcon = make_connection(p->n, uri);
    evhttp_make_request(evcon, p->direct_req, EVHTTP_REQ_GET, request_uri);
    debug("p:%p con:%p direct request submitted: %s\n", p, evhttp_request_get_connection(p->direct_req), evhttp_request_get_uri(p->direct_req));
}

address parse_address(const char *addr)
{
    address a;
    char *port = strchr(addr, ':');
    *port = '\0';
    a.ip = inet_addr(addr);
    a.port = htons(atoi(port+1));
    return a;
}

void proxy_submit_request_on_con(proxy_request *p, const evhttp_uri *uri, evhttp_connection *evcon)
{
    p->proxy_req = evhttp_request_new(proxy_request_done_cb, p);
    const char *request_header_whitelist[] = {"Referer"};
    for (size_t i = 0; i < lenof(request_header_whitelist); i++) {
        copy_header(p->server_req, p->proxy_req, request_header_whitelist[i]);
    }
    overwrite_header(p->proxy_req, "Proxy-Connection", "Keep-Alive");

    evhttp_request_set_header_cb(p->proxy_req, proxy_header_cb);
    evhttp_request_set_error_cb(p->proxy_req, proxy_error_cb);

    p->proxy_head_req = evhttp_request_new(proxy_request_done_cb, p);
    copy_all_headers(p->proxy_req, p->proxy_head_req);

    evhttp_request_set_header_cb(p->proxy_head_req, proxy_header_cb);
    evhttp_request_set_error_cb(p->proxy_head_req, proxy_head_error_cb);

    char request_uri[2048];
    evhttp_uri_join(uri, request_uri, sizeof(request_uri));
    evhttp_make_request(evcon, p->proxy_req, EVHTTP_REQ_GET, request_uri);
    evhttp_make_request(evcon, p->proxy_head_req, EVHTTP_REQ_HEAD, request_uri);
    debug("p:%p con:%p proxy request submitted: %s\n", p, evhttp_request_get_connection(p->proxy_req), evhttp_request_get_uri(p->proxy_req));
}

void proxy_submit_request(proxy_request *p, const evhttp_uri *uri)
{
    assert(!p->proxy_req);

    const char *xdht = evhttp_find_header(evhttp_request_get_input_headers(p->server_req), "X-DHT");
    if (!xdht) {
        const char *xpeer = evhttp_find_header(evhttp_request_get_input_headers(p->server_req), "X-Peer");
        if (xpeer) {
            address a = parse_address(xpeer);
            add_addresses(&all_peers, &all_peers_len, (const byte*)&a, 1);
            for (size_t i = 0; i < all_peers_len; i++) {
                if (!memeq((const uint8_t *)&a, (const uint8_t *)&all_peers[i].addr, sizeof(address))) {
                    continue;
                }
                p->peer = &all_peers[i];
                address *a = &p->peer->addr;
                sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
                debug("X-Peer %s:%d\n", inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
                proxy_submit_request_on_con(p, uri, evhttp_utp_create(p->n, (sockaddr*)&sin, sizeof(sin)));
                break;
            }
            return;
        }
        evhttp_connection *evcon = injector_connection(p->n, &p->peer);
        if (evcon) {
            p->injector = true;
            proxy_submit_request_on_con(p, uri, evcon);
            return;
        }
        evcon = injector_proxy_connection(p->n, &p->peer);
        if (evcon) {
            p->injector = false;
            proxy_submit_request_on_con(p, uri, evcon);
            return;
        }
    }

    p->dht_lookup_running = true;
    __block bool dht_lookup_cancelled = p->dht_lookup_cancelled;
    fetch_url_swarm(p->n, evhttp_request_get_uri(p->server_req), ^(const byte *peers, uint num_peers) {
        if (peers) {
            add_addresses(&all_peers, &all_peers_len, peers, num_peers);
        }
        if (dht_lookup_cancelled) {
            return;
        }
        if (p->dht_lookup_cancelled) {
            p->dht_lookup_running = false;
            dht_lookup_cancelled = true;
            return;
        }
        // for now, one response is enough
        p->dht_lookup_running = false;
        dht_lookup_cancelled = true;
        if (peers) {
            for (size_t i = 0; i < all_peers_len; i++) {
                if (!memeq(peers, (const uint8_t *)&all_peers[i].addr, sizeof(address))) {
                    continue;
                }
                p->peer = &all_peers[i];
                address *a = &p->peer->addr;
                sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
                debug("DHT peer %s:%d\n", inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
                proxy_submit_request_on_con(p, uri, evhttp_utp_create(p->n, (sockaddr*)&sin, sizeof(sin)));
                break;
            }
        } else {
            evhttp_connection *evcon = peer_connection(p->n, all_peers, all_peers_len, &p->peer);
            if (evcon) {
                address *a = &p->peer->addr;
                sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
                debug("DHT peer %s:%d\n", inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
                proxy_submit_request_on_con(p, uri, evcon);
            } else {
                debug("p:%p could not find peers\n", p);
                proxy_request_cleanup(p);
            }
        }
    });
}

void server_error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p server_error_cb %d\n", p, error);
    p->server_req = NULL;
    p->dont_free = true;
    if (p->direct_req) {
        evhttp_cancel_request(p->direct_req);
        p->direct_req = NULL;
    }
    proxy_cancel_proxy(p);
    p->dont_free = false;
    proxy_request_cleanup(p);
}

void server_handle_request(struct evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    p->evhttp_handle_request(req, p->n->http);
}

void submit_request(network *n, evhttp_request *server_req, const evhttp_uri *uri)
{
    proxy_request *p = alloc(proxy_request);
    p->n = n;
    snprintf(p->cache_name, sizeof(p->cache_name), CACHE_NAME);
    p->cache_file = -1;
    p->server_req = server_req;
    p->evhttp_handle_request = p->server_req->cb;
    p->server_req->cb = server_handle_request;
    p->server_req->cb_arg = p;
    evhttp_request_set_error_cb(p->server_req, server_error_cb);

    evhttp_connection *evcon = evhttp_request_get_connection(server_req);

    // https://github.com/libevent/libevent/issues/510
    int fd = bufferevent_getfd(evhttp_connection_get_bufferevent(evcon));
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    getpeername(fd, (sockaddr *)&ss, &len);
    const char *xdht = evhttp_find_header(evhttp_request_get_input_headers(server_req), "X-DHT");
    const char *xpeer = evhttp_find_header(evhttp_request_get_input_headers(server_req), "X-Peer");
    if (try_direct && !xdht && !xpeer && addr_is_localhost((sockaddr *)&ss, len)) {
        direct_submit_request(p, uri);
    }
    proxy_submit_request(p, uri);
}

typedef struct {
    evhttp_request *server_req;
    evhttp_request *proxy;
    bufferevent *direct;
    peer *peer;
} connect_req;

void connect_cleanup(connect_req *c)
{
    if (c->direct || c->proxy) {
        return;
    }
    if (c->server_req) {
        evhttp_send_error(c->server_req, 502, "Bad Gateway");
    }
    free(c);
}

void connected(connect_req *c, bufferevent *other)
{
    debug("c:%p connected %p\n", c, other);
    evhttp_connection *evcon = evhttp_request_get_connection(c->server_req);
    if (!evcon) {
        // XXX: could remove this case by using the error_cb hack
        c->server_req = NULL;
        bufferevent_free(other);
        return;
    }
    bufferevent *bev = evhttp_connection_detach_bufferevent(evcon);
    c->server_req = NULL;
    connect_cleanup(c);
    evbuffer_add_printf(bufferevent_get_output(bev), "HTTP/1.0 200 Connection established\r\n\r\n");
    bev_splice(bev, other);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    bufferevent_enable(other, EV_READ|EV_WRITE);
}

int connect_header_cb(evhttp_request *req, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p connect_header_cb %d %s\n", c, evhttp_request_get_response_code(req), evhttp_request_get_response_code_line(req));
    if (evhttp_request_get_response_code(req) != 200) {
        return -1;
    }

    c->peer->last_connect = time(NULL);

    if (c->direct) {
        bufferevent_free(c->direct);
        c->direct = NULL;
    }

    bufferevent *other = evhttp_connection_detach_bufferevent(evhttp_request_get_connection(req));
    connected(c, other);
    return -1;
}

void connect_error_cb(enum evhttp_request_error error, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p connect_error_cb %d\n", c, error);
    c->proxy = NULL;
    connect_cleanup(c);
}

void connect_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("connect_event_cb events:%x bev:%p req:%s\n", events, bev, evhttp_request_get_uri(c->server_req));

    if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
        c->direct = NULL;
        connect_cleanup(c);
    } else if (events & BEV_EVENT_CONNECTED) {
        if (c->proxy) {
            evhttp_cancel_request(c->proxy);
            c->proxy = NULL;
        }
        c->direct = NULL;
        connected(c, bev);
    }
}

void connect_request(network *n, evhttp_request *req)
{
    char buf[2048];
    snprintf(buf, sizeof(buf), "https://%s", evhttp_request_get_uri(req));
    evhttp_uri *uri = evhttp_uri_parse(buf);
    const char *host = evhttp_uri_get_host(uri);
    if (!host) {
        evhttp_uri_free(uri);
        evhttp_send_error(req, 502, "Bad Gateway");
        return;
    }
    int port = evhttp_uri_get_port(uri);
    if (port == -1) {
        port = 443;
    } else if (port != 443) {
        evhttp_uri_free(uri);
        evhttp_send_error(req, 502, "Bad Gateway");
        return;
    }

    connect_req *c = alloc(connect_req);
    c->server_req = req;

    c->direct = bufferevent_socket_new(n->evbase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(c->direct, NULL, NULL, connect_event_cb, c);
    bufferevent_socket_connect_hostname(c->direct, n->evdns, AF_INET, host, port);
    evhttp_uri_free(uri);
    bufferevent_enable(c->direct, EV_READ);

    evhttp_connection *evcon = injector_proxy_connection(n, &c->peer);
    if (!evcon) {
        evcon = injector_connection(n, &c->peer);
        if (!evcon) {
            debug("c:%p could not find peers\n", c);
            connect_cleanup(c);
            return;
        }
    }
    c->proxy = evhttp_request_new(NULL, c);
    evhttp_request_set_header_cb(c->proxy, connect_header_cb);
    evhttp_request_set_error_cb(c->proxy, connect_error_cb);
    evhttp_make_request(evcon, c->proxy, EVHTTP_REQ_CONNECT, evhttp_request_get_uri(req));
}

int evhttp_parse_headers_(struct evhttp_request *, struct evbuffer*);

void http_request_cb(evhttp_request *req, void *arg)
{
    network *n = (network*)arg;
    debug("con:%p request received: %s\n", evhttp_request_get_connection(req), evhttp_request_get_uri(req));
    if (evhttp_request_get_command(req) == EVHTTP_REQ_CONNECT) {
        connect_request(n, req);
        return;
    }

    const char *xcache = evhttp_find_header(evhttp_request_get_input_headers(req), "X-Cache");
    const char *xdht = evhttp_find_header(evhttp_request_get_input_headers(req), "X-DHT");
    const char *xpeer = evhttp_find_header(evhttp_request_get_input_headers(req), "X-Peer");
    if (xcache || (!xdht && !xpeer)) {
        char *uri = evhttp_encode_uri(evhttp_request_get_uri(req));
        char cache_path[2048];
        char cache_headers_path[2048];
        snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, uri);
        snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
        free(uri);
        int cache_file = open(cache_path, O_RDONLY);
        int headers_file = open(cache_headers_path, O_RDONLY);
        debug("check hit:%d,%d cache:%s\n", cache_file != -1, headers_file != -1, cache_path);
        if (cache_file != -1 && headers_file != -1) {
            evhttp_request *temp = evhttp_request_new(NULL, NULL);
            evbuffer *header_buf = evbuffer_new();
            off_t length = lseek(headers_file, 0, SEEK_END);
            evbuffer_add_file(header_buf, headers_file, 0, length);
            evhttp_parse_headers_(temp, header_buf);
            copy_response_headers(temp, req);
            evhttp_request_free(temp);
            evbuffer_free(header_buf);

            evbuffer *content = evbuffer_new();
            length = lseek(cache_file, 0, SEEK_END);
            evbuffer_add_file(content, cache_file, 0, length);
            debug("responding with %d %s %u\n", HTTP_OK, "OK", length);
            evhttp_send_reply(req, HTTP_OK, "OK", content);
            evbuffer_free(content);
            return;
        }
        close(cache_file);
        close(headers_file);
    }
    if (xcache) {
        evhttp_send_error(req, 502, "Bad Gateway");
        return;
    }

    submit_request(n, req, evhttp_request_get_evhttp_uri(req));
}

void client_init(port_t port)
{
    network *n = network_setup("0.0.0.0", port);

    utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    evhttp_set_allowed_methods(n->http, EVHTTP_REQ_GET | EVHTTP_REQ_CONNECT);
    evhttp_set_gencb(n->http, http_request_cb, n);
    evhttp_bind_socket_with_handle(n->http, "0.0.0.0", port);
    printf("listening on TCP:%s:%d\n", "0.0.0.0", port);

    timer_callback cb = ^{
        dht_get_peers(n->dht, injector_swarm, ^(const byte *peers, uint num_peers) {
            if (peers) {
                add_addresses(&injectors, &injectors_len, peers, num_peers);
            }
        });
        update_injector_proxy_swarm(n);
    };
    cb();
    timer_repeating(n, 25 * 60 * 1000, cb);

    g_n = n;
}

int client_run()
{
    return network_loop(g_n);
}

int main(int argc, char *argv[])
{
    char *port_s = "8006";

    o_debug = 1;

    for (;;) {
        int c = getopt(argc, argv, "np:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'p':
            port_s = optarg;
            break;
        case 'n':
            try_direct = false;
            break;
        default:
            die("Unhandled argument: %c\n", c);
        }
    }

    client_init(atoi(port_s));
    return client_run();
}
