//*

// #include "utils.hpp"
#include <iostream>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

#include <math.h>
#include <fcntl.h>          // File descriptor control
#include <poll.h>           // FD polling
#include <unistd.h>         // Read & write functions
#include <arpa/inet.h>      // Internet operations
// #include <sys/socket.h>     // ...
// #include <netinet/ip.h>     // ...

#include "common.h"
#include "hashtable.h"
#include "heap.h"
#include "list.h"
#include "zset.h"

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d], %s\n", err, msg);
    abort();
}

const uint64_t k_idle_timeout_ms = 5 * 1000;

// Connection state
enum {
    STATE_REQ = 0,
    STATE_RES = 1,
    STATE_END = 2,
};

// ...
enum {
    RES_OK = 0,
    RES_ERR = 1,
    RES_NX = 2,
};

enum {
    ERR_UNKNOWN = 1,
    ERR_2BIG = 2,
    ERR_TYPE = 3,
    ERR_ARG = 4,
};

enum {
    T_STR = 0,
    T_ZSET = 1,
};

struct Conn {
    int fd = -1;
    uint32_t state = 0; // STATE_REQ or STATE_RES,, why 32 bits?

    // String buffer for reading
    size_t rbuf_size = 0;
    uint8_t rbuf[4 + k_max_msg];

    // String buffer for writing
    size_t wbuf_size = 0;
    size_t wbuf_sent = 0;
    uint8_t wbuf[4 + k_max_msg];

    uint64_t idle_start = 0;
    DList idle_list;
};

// Entry struct (intrusive data structure)
struct Entry {
    struct HNode node;
    std::string key;
    std::string val;
    uint32_t type = 0;
    ZSet *zset = NULL;
    size_t heap_idx = -1; // TTL - index of HeapItem
};

// Global data - Key space,, connnection map, timers,, TTL timers
static struct {
    HMap db;
    std::vector<Conn *> fd2conn;
    DList idle_list;
    std::vector<HeapItem> heap;
} g_data;

// [Get time] - monotonic timestamp
static uint64_t get_monotonic_usec() {
    timespec tv = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return uint64_t(tv.tv_sec) * 1000000 + tv.tv_nsec / 1000;
}

// Set to nonblocking
static void fd_set_nb(int fd) {
    errno = 0;
    // Get fd status flags
    int flags = fcntl(fd, F_GETFL, 0);
    if (errno) {
        die("fcntl error");
        return;
    }

    // Set variable flags to nonblocking & set fd
    flags |= O_NONBLOCK;

    errno = 0;
    (void)fcntl(fd, F_SETFL, flags);
    if (errno)
        die("fcntl error");
}
    
// Push conn struct into fd map
static void conn_put(std::vector<Conn *> &fd2conn, struct Conn *conn) {
    if (fd2conn.size() <= (size_t)conn->fd)
        fd2conn.resize(conn->fd + 1);
    fd2conn[conn->fd] = conn;
}

// Accept new connection given fd
static int32_t accept_new_conn(int fd) {
    // Create socket address & connection fd
    struct sockaddr_in client_addr = {};
    socklen_t socklen = sizeof(client_addr);
    int connfd = accept(fd, (struct sockaddr *)&client_addr, &socklen);
    if (connfd < 0) {
        msg("accept() error");
        return -1;
    }

    // Set to nonblocking and create struct
    fd_set_nb(connfd);
    struct Conn *conn = (struct Conn *)malloc(sizeof(struct Conn));
    if (!conn) {
        close(connfd);
        return -1;
    }

    conn->fd = connfd;
    conn->state = STATE_REQ;
    conn->rbuf_size = 0;
    conn->wbuf_size = 0;
    conn->wbuf_sent = 0;
    conn->idle_start = get_monotonic_usec();
    dlist_insert_before(&g_data.idle_list, &conn->idle_list);
    conn_put(g_data.fd2conn, conn);
    return 0;
}

static void state_req(Conn *conn);
static void state_res(Conn *conn);

// Placeholder key space
static std::map<std::string, std::string> g_map;

static bool cmd_is(const std::string &word, const char *cmd) {
    return 0 == strcasecmp(word.c_str(), cmd);
}

// Parse into vector - information from client request
static int32_t parse_req(
    const uint8_t *data, size_t len, std::vector<std::string> &out)
{
    if (len < 4)
        return -1;
    uint32_t n = 0;

    // Copy 1st argument of protocol - number of strings
    memcpy(&n, &data[0], 4);
    if (n > k_max_args)
        return -1;
    
    size_t pos = 4;
    while (n--) {
        if (pos + 4 > len)
            return -1;
        uint32_t sz = 0;

        // Copy argument size to data
        memcpy(&sz, &data[pos], 4);
        if (pos + 4 + sz > len)
            return -1;

        // Copy argument body to data
        out.push_back(std::string((char *)&data[pos + 4], sz));
        pos += 4 + sz;
    }

    // Check for trailing garbage data
    if (pos != len)
        return -1;
    return 0;
}

// Hash node data comparison
static bool entry_eq(HNode *lhs, HNode *rhs) {
    struct Entry *le = container_of(lhs, struct Entry, node);
    struct Entry *re = container_of(rhs, struct Entry, node);
    return lhs->hcode == rhs->hcode && le->key == re->key;
}

static void out_nil(std::string &out) {
    out.push_back(SER_NIL);
}

static void out_str(std::string &out, const char *s, size_t size) {
    out.push_back(SER_STR);
    uint32_t len = (uint32_t)size;
    out.append((char *)&len, 4);
    out.append(s, len);
}

static void out_str(std::string &out, const std::string &val){
    return out_str(out, val.data(), val.size());
}

static void out_int(std::string &out, int64_t val) {
    out.push_back(SER_INT);
    out.append((char *)&val, 8);
}

static void out_dbl(std::string &out, double val) {
    out.push_back(SER_DBL);
    out.append((char *)&val, 8);
}

static void out_err(std::string &out, int32_t code, const std::string &msg) {
    out.push_back(SER_ERR);
    out.append((char *)&code, 4);
    uint32_t len = (uint32_t)msg.size();
    out.append((char *)&len, 4);
    out.append(msg);
}

static void out_arr(std::string &out, uint32_t n) {
    out.push_back(SER_ARR);
    out.append((char *)&n, 4);
}

// Update & set output
static void out_update_arr(std::string &out, uint32_t n) {
    assert(out[0] == SER_ARR);
    memcpy(&out[1], &n, 4);
}

// Scan hashtable
static void h_scan(HTab *tab, void (*f)(HNode *, void *), void *arg) {
    if (tab->size == 0)
        return;
    for (size_t i = 0; i < tab->mask + 1; ++i) {
        HNode *node = tab->tab[i];
        while (node) {
            f(node, arg);
            node = node->next;
        }
    }
}

// Append key to output string
static void cb_scan(HNode *node, void *arg) {
    std::string &out = *(std::string *)arg;
    out_str(out, container_of(node, Entry, node)->key);
}

static void do_get(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (!node)
        return out_nil(out);
    
    const std::string &val = container_of(node, Entry, node)->val;
    out_str(out, val);
}

static void do_set(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (node)
        container_of(node, Entry, node)->val.swap(cmd[2]);
    else {
        Entry *ent = new Entry();
        ent->key.swap(key.key);
        ent->node.hcode = key.node.hcode;
        ent->val.swap(cmd[2]);
        hm_insert(&g_data.db, &ent->node);
    }
    return out_nil(out);
}

static void do_del (std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_pop(&g_data.db, &key.node, &entry_eq);
    if (node)
        delete container_of(node, Entry, node);

    // Return whether deletion took place
    return out_int(out, node ? 1 : 0);
}

// List all keys - scan both hashtables
static void do_keys(std::vector<std::string> &cmd, std::string &out) {
    (void)cmd;
    out_arr(out, (uint32_t)hm_size(&g_data.db));
    h_scan(&g_data.db.ht1, &cb_scan, &out);
    h_scan(&g_data.db.ht2, &cb_scan, &out);
}

// Set/remove TTL
static void entry_set_ttl(Entry *ent, int64_t ttl_ms) {
    if (ttl_ms < 0 && ent->heap_idx != (size_t)-1) {
        // Erase last item in heap, replace w/ last item array
        size_t pos = ent->heap_idx;
        g_data.heap[pos] = g_data.heap.back();
        g_data.heap.pop_back();
        if (pos < g_data.heap.size())
            heap_update(g_data.heap.data(), pos, g_data.heap.size());
        ent->heap_idx = -1;
    } else if (ttl_ms >= 0) {
        size_t pos = ent->heap_idx;
        if (pos == (size_t)-1) {
            // Add new item
            HeapItem item;
            item.ref = &ent->heap_idx;
            g_data.heap.push_back(item);
            pos = g_data.heap.size() - 1;
        }
        g_data.heap[pos].val = get_monotonic_usec() + (uint64_t)ttl_ms * 1000;
        heap_update(g_data.heap.data(), pos, g_data.heap.size());
    }
}

// Remove TTL with Entry
static void entry_del(Entry *ent) {
    switch (ent->type) {
    case T_ZSET:
        zset_dispose(ent->zset);
        delete ent->zset;
        break;
    }
    entry_set_ttl(ent, -1);
    delete ent;
}

static bool str2dbl(const std::string &s, double &out) {
    char *endp = NULL;
    out = strtod(s.c_str(), &endp);
    return endp == s.c_str() + s.size() && !isnan(out);
}

static bool str2int(const std::string &s, int64_t &out) {
    char *endp = NULL;
    out = strtoll(s.c_str(), &endp, 10);
    return endp == s.c_str() + s.size();
}

// [Update & query TTLs]
static void do_expire(std::vector<std::string> &cmd, std::string &out) {
    int64_t ttl_ms = 0;
    if (!str2int(cmd[2], ttl_ms))
        return out_err(out, ERR_ARG, "expect int64");
    
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (node) {
        Entry *ent = container_of(node, Entry, node);
        entry_set_ttl(ent, ttl_ms);
    }

    return out_int(out, node ? 1 : 0);
}

static void do_ttl(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (!node)
        return out_int(out, -2);
    
    Entry *ent = container_of(node, Entry, node);
    if (ent->heap_idx == (size_t)-1)
        return out_int(out, -1);
    
    uint64_t expire_at = g_data.heap[ent->heap_idx].val;
    uint64_t now_us = get_monotonic_usec();
    return out_int(out, expire_at > now_us ? (expire_at - now_us) / 1000 : 0);
}

// zadd, zset, score, name
static void do_zadd(std::vector<std::string> &cmd, std::string &out) {
    double score = 0;
    if (!str2dbl(cmd[2], score))
        return out_err(out, ERR_ARG, "expect fp number");
    
    // Look up/create zset
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());
    HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);

    Entry *ent = NULL;
    if (!hnode) {
        ent = new Entry();
        ent->key.swap(key.key);
        ent->node.hcode = key.node.hcode;
        ent->type = T_ZSET;
        ent->zset = new ZSet();
        hm_insert(&g_data.db, &ent->node);
    } else {
        ent = container_of(hnode, Entry, node);
        if (ent->type != T_ZSET)
            return out_err(out, ERR_TYPE, "expect zset");
    }

    // Add/update tuple
    const std::string &name = cmd[3];
    bool added = zset_add(ent->zset, name.data(), name.size(), score);
    return out_int(out, (int64_t)added);
}

static bool expect_zset(std::string &out, std::string &s, Entry **ent) {
    Entry key;
    key.key.swap(s);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());
    HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (!hnode) {
        out_nil(out);
        return false;
    }

    *ent = container_of(hnode, Entry, node);
    if ((*ent)->type != T_ZSET) {
        out_err(out, ERR_TYPE, "expect zset");
        return false;
    }
    return true;
}

// zremove, zset, name
static void do_zrem(std::vector<std::string> &cmd, std::string &out) {
    Entry *ent = NULL;
    if (!expect_zset(out, cmd[1], &ent))
        return;

    const std::string &name = cmd[2];
    ZNode *znode = zset_pop(ent->zset, name.data(), name.size());
    if (znode)
        znode_del(znode);
    
    return out_int(out, znode ? 1 : 0);
}

// zscore, zset, name
static void do_zscore(std::vector<std::string> &cmd, std::string &out) {
    Entry *ent = NULL;
    if (!expect_zset(out, cmd[1], &ent))
        return;

    const std::string &name = cmd[2];
    ZNode *znode = zset_lookup(ent->zset, name.data(), name.size());
    return znode ? out_dbl(out, znode->score) : out_nil(out);
}

// zquery, zset, score, name, offset, limit
static void do_zquery(std::vector<std::string> &cmd, std::string &out) {
    // Parse
    double score = 0;
    if (!str2dbl(cmd[2], score))
        return out_err(out, ERR_ARG, "expect fp number");
    
    const std::string &name = cmd[3];
    int64_t offset = 0;
    int64_t limit = 0;
    if (!str2int(cmd[4], offset))
        return out_err(out, ERR_ARG, "expect int");
    if (!str2int(cmd[5], limit))
        return out_err(out, ERR_ARG, "expect int");

    // Get zset
    Entry *ent = NULL;
    if (!expect_zset(out, cmd[1], &ent)) {
        if(out[0] == SER_NIL) {
            out.clear();
            out_arr(out, 0);
        }
        return;
    }

    // Lookup tuple
    if (limit <= 0)
        return out_arr(out, 0);
    ZNode *znode = zset_query(
        ent->zset, score, name.data(), name.size(), offset
    );

    // Output
    out_arr(out, 0);
    uint32_t n = 0;
    while (znode && (int64_t)n < limit) {
        out_str(out, znode->name, znode->len);
        out_dbl(out, znode->score);
        znode = container_of(avl_offset(&znode->tree, +1), ZNode, tree);
        n += 2;
    }
    return out_update_arr(out, n);
}

// Determine request
static void do_request(std::vector<std::string> &cmd, std::string &out) {
    if (cmd.size() == 1 && cmd_is(cmd[0], "keys"))
        do_keys(cmd, out); 
    else if (cmd.size() == 2 && cmd_is(cmd[0], "get"))
        do_get(cmd, out);
    else if (cmd.size() == 3 && cmd_is(cmd[0], "set"))
        do_set(cmd, out);
    else if (cmd.size() == 2 && cmd_is(cmd[0], "del"))
        do_del(cmd, out);
    else if (cmd.size() == 4 && cmd_is(cmd[0], "zadd"))
        do_zadd(cmd, out);
    else if (cmd.size() == 3 && cmd_is(cmd[0], "zrem"))
        do_zrem(cmd, out);
    else if (cmd.size() == 3 && cmd_is(cmd[0], "zscore"))
        do_zscore(cmd, out);
    else if (cmd.size() == 6 && cmd_is(cmd[0], "zquery")) {
        do_zquery(cmd, out);
    } else {
        // Command not recognized
        out_err(out, ERR_UNKNOWN, "Unknown cmd");
    }
}

// Parse buffer request
static bool try_one_request(Conn *conn) {

    // Request too small -> retry
    if (conn->rbuf_size < 4)
        return false;
    uint32_t len = 0;

    // Get data length
    memcpy(&len, &conn->rbuf[0], 4);

    if (len > k_max_msg) {
        msg("too long");
        conn->state = STATE_END;
        return false;
    }

    // Not enough data -> retry
    if (4 + len > conn->rbuf_size)
        return false;
    
    // Parse request
    std::vector<std::string> cmd;
    if  (0 != parse_req(&conn->rbuf[4], len, cmd)) {
        msg("bad req");
        conn->state = STATE_END;
        return false;
    }

    // Get request and generate response
    std::string out;
    do_request(cmd, out);

    // Pack response into buffer
    if (4 + out.size() > k_max_msg) {
        out.clear();
        out_err(out, ERR_2BIG, "response is too big");
    }
    uint32_t wlen = (uint32_t)out.size();
    memcpy(&conn->wbuf[0], &wlen, 4);
    memcpy(&conn->wbuf[4], out.data(), out.size());
    conn->wbuf_size = 4 + wlen;

    // Remove request from buffer
    size_t remain = conn->rbuf_size - 4 - len;
    if (remain) {
        // ** Memmove only before read (as opposed to every request) **
        memmove(conn->rbuf, &conn->rbuf[4 + len], remain);
    }
    conn->rbuf_size = remain;

    // Change state
    conn->state = STATE_RES;
    state_res(conn);

    return (conn->state == STATE_REQ);
}

// ...
static bool try_fill_buffer(Conn *conn) {
    // ...
    assert(conn->rbuf_size <sizeof(conn->rbuf));
    ssize_t rv = 0;

    do {
        size_t cap = sizeof(conn->rbuf) - conn->rbuf_size;
        rv = read(conn->fd, &conn->rbuf[conn->rbuf_size], cap);
    } while (rv < 0 && errno == EINTR);
    if (rv < 0) {
        if (errno == EAGAIN)
            return false;
        msg("read() error");
        conn->state = STATE_END;
        return false;
    }
    if (rv == 0) {
        if (conn->rbuf_size > 0)
            msg("unexpected EOF");
        else   
            msg("EOF");
        conn->state = STATE_END;
        return false;
    }

    conn->rbuf_size += (size_t)rv;
    assert(conn->rbuf_size <= sizeof(conn->rbuf));

    // Process requests one by one
    while (try_one_request(conn)) {}
    return (conn->state == STATE_REQ);
}

// ...
static bool try_flush_buffer(Conn *conn) {
    ssize_t rv = 0;
    do {
        size_t remain = conn->wbuf_size - conn->wbuf_sent;
        rv = write(conn->fd, &conn->wbuf[conn->wbuf_sent], remain);
    } while (rv < 0 && errno == EINTR);

    if (rv < 0) {
        if (errno == EAGAIN)
            return false;
        msg("write() error");
        conn->state = STATE_END;
        return false;
    }

    conn->wbuf_sent += (size_t)rv;
    assert(conn->wbuf_sent <= conn->wbuf_size);
    if (conn->wbuf_sent == conn->wbuf_size) {
        // Response fully sent & change state back
        conn->state = STATE_REQ;
        conn->wbuf_sent = 0;
        conn->wbuf_size = 0;
        return false;
    }

    // Still have data
    return true;
}

// ...
static void state_req(Conn *conn) {
    while (try_fill_buffer(conn)) {}
}

// ...
static void state_res(Conn *conn) {
    // ** Buffer multiple responses and write once **
    while (try_flush_buffer(conn)) {}
}

// [State machine for client connections]
static void connection_io(Conn *conn) {
    // Conn awoken by poll -> timer moved to end of list
    conn->idle_start = get_monotonic_usec();
    dlist_detach(&conn->idle_list);
    dlist_insert_before(&g_data.idle_list, &conn->idle_list);

    if (conn->state == STATE_REQ)
        state_req(conn);
    else if (conn->state == STATE_RES)
        state_res(conn);
    else
        assert(0);
}

// Take first/nearest timer value and use to calculate poll timeout
static uint32_t next_timer_ms() {
    uint64_t now_us = get_monotonic_usec();
    uint64_t next_us = (uint64_t)-1;

    // Idle timers
    if (!dlist_empty(&g_data.idle_list)) {
        Conn *next = container_of(g_data.idle_list.next, Conn, idle_list);
        next_us = next->idle_start + k_idle_timeout_ms * 1000;
    }
    
    // TTL timers
    if (!g_data.heap.empty() && g_data.heap[0].val < next_us)
        next_us = g_data.heap[0].val;
    
    if (next_us == (uint64_t)-1)
        return 10000; // No timer - arbitrary value

    if (next_us <= now_us)
        return 0; // Missed
    
    return (uint32_t)((next_us - now_us) / 1000);
}

// Remove connection from list
static void conn_done(Conn *conn) {
    g_data.fd2conn[conn->fd] = NULL;
    (void)close(conn->fd);
    dlist_detach(&conn->idle_list);
    free(conn);
}

static bool hnode_same(HNode *lhs, HNode *rhs) {
    return lhs == rhs;
}

// Check timer list to fire in due time
static void process_timers() {
    // +1000ms for ms resolution of poll()
    uint64_t now_us = get_monotonic_usec() + 1000;

    // Idle timers
    while (!dlist_empty(&g_data.idle_list)) {
        Conn *next = container_of(g_data.idle_list.next, Conn, idle_list);
        uint64_t next_us = next->idle_start + k_idle_timeout_ms * 1000;
        if (next_us >= now_us)
            break; // Not ready
        
        printf("removing idle connection: %d\n", next->fd);
        conn_done(next);
    }

    // TTL timers
    const size_t k_max_works = 2000;
    size_t nworks = 0;
    while (!g_data.heap.empty() && g_data.heap[0].val < now_us) {
        Entry *ent = container_of(g_data.heap[0].ref, Entry, heap_idx);
        HNode *node = hm_pop(&g_data.db, &ent->node, &hnode_same);
        assert(node == &ent->node);
        entry_del(ent);
        if (nworks++ >= k_max_works)
            break; // Don't stall server if too many keys are expiring at once
    }
}

int main() {
    dlist_init(&g_data.idle_list);
    // Retrieve file desciptor - handler for given type of i/o resource
    // Parameters set IPv4 TCP socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        die("socket()");
    
    // Introduce syscall,, params configure socket
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    // Bind - Associate address to socket fd
    // We configure the IPv4 wildcard address 0.0.0.0:1234
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    // [Convert from network to host byte order] - port & address
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0);
    int rv = bind(fd, (const sockaddr *)&addr, sizeof(addr));
    if (rv)
        die("bind()");
    
    // Listen - Accept connections to address
    rv = listen(fd, SOMAXCONN);
    if (rv)
        die("listen()");

    fd_set_nb(fd);                        // Set to nonblocking

    // Event loop: General idea is to seach for active fds by polling and operate.
    std::vector<struct pollfd> poll_args; // Poll request arguments - fd, [status of data], ?
    while (true) {
        poll_args.clear();
        // Listening [socket] fd in first position
        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);
        
        // Connection fds
        for (Conn *conn : g_data.fd2conn) {
            if (!conn)
                continue;
            struct pollfd pfd = {};
            pfd.fd = conn->fd;
            pfd.events = (conn->state == STATE_REQ) ? POLLIN : POLLOUT;
            pfd.events = pfd.events | POLLERR;
            poll_args.push_back(pfd);
        }

        // Poll for active fds
        // ** Replace with epoll **
        int timeout_ms = (int)next_timer_ms();
        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), timeout_ms);
        if (rv < 0)
            die("poll");
        
        // Process active connections
        for (size_t i = 1; i < poll_args.size(); i++) {
            if (poll_args[i].revents) {
                Conn *conn = g_data.fd2conn[poll_args[i].fd];
                connection_io(conn);
                if (conn->state == STATE_END) {
                    // Destroy
                    conn_done(conn);
                }
            }
        }

        process_timers();

        // Accept new connection if listening fd is active
        if (poll_args[0].revents)
            (void)accept_new_conn(fd);
    }

    return 0;
}

//*/