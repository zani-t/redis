// #include "utils.hpp"
#include <iostream>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

// #include <stdint.h>         // ...
#include <fcntl.h>          // File descriptor control
#include <poll.h>           // FD polling
#include <unistd.h>         // Read & write functions
#include <arpa/inet.h>      // Internet operations
// #include <sys/socket.h>     // ...
// #include <netinet/ip.h>     // ...

// EXPORT
const size_t k_max_msg = 4096;
const size_t k_max_args = 1024;

enum {
    STATE_REQ = 0,
    STATE_RES = 1,
    STATE_END = 2,
};

enum {
    RES_OK = 0,
    RES_ERR = 1,
    RES_NX = 2,
};

// ...
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
};

// EXPORT
static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

// EXPORT
static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d], %s\n", err, msg);
    abort();
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

/*  In order to process requests separately we create a request protocol
    of a 4-byte header containing the message length, followed by the
    variable-length message itself. 
static int32_t one_request(int connfd) {
    char rbuf[4 + k_max_msg + 1];
    errno = 0;
    int32_t err = read_full(connfd, rbuf, 4);
    if (err) {
        if (errno == 0)
            msg("EOF");
        else
            msg("read() error (head)");
        return err;
    }

    // Get header describing length [little endian]
    // memcpy after error handling?
    uint32_t len = 0;
    memcpy(&len, rbuf, 4);
    if (len > k_max_msg) {
        msg("too long");
        return -1;
    }

    // Read request body
    err = read_full(connfd, &rbuf[4], len);
    if (err) {
        msg("read() error (body)");
        return err;
    }

    // Action - show request
    rbuf[4 + len] = '\0';
    printf("client says: %s\n", &rbuf[4]);

    // Reply using same protocol
    const char reply[] = "world";
    char wbuf[4 + sizeof(reply)];
    len = (uint32_t)strlen(reply);
    memcpy(wbuf, &len, 4);
    memcpy(&wbuf[4], reply, len);
    return write_all(connfd, wbuf, 4 + len);
} */

// Push conn struct into fd map
static void conn_put(std::vector<Conn *> &fd2conn, struct Conn *conn) {
    if (fd2conn.size() <= (size_t)conn->fd)
        fd2conn.resize(conn->fd + 1);
    fd2conn[conn->fd] = conn;
}

// Accept new connection given fd
static int32_t accept_new_conn(std::vector<Conn *> &fd2conn, int fd) {
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
    conn_put(fd2conn, conn);
    return 0;
}

static void state_req(Conn *conn);
static void state_res(Conn *conn);

// Placeholder key space
static std::map<std::string, std::string> g_map;

static bool cmd_is(const std::string &word, const char *cmd) {
    return 0 == strcasecmp(word.c_str(), cmd);
}

// EXPORT
// Get value command
static uint32_t do_get(
    const std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen)
{
    if (!g_map.count(cmd[1]))
        return RES_NX;
    std::string &val = g_map[cmd[1]];
    assert(val.size() <= k_max_msg);
    memcpy(res, val.data(), val.size());
    *reslen = (uint32_t)val.size();
    return RES_OK;
}

// EXPORT
// Set value command
static uint32_t do_set(
    const std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen)
{
    (void)res;
    (void)reslen;
    g_map[cmd[1]] = cmd[2];
    return RES_OK;
}

// EXPORT
// Delete key command
static uint32_t do_del(
    const std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen)
{
    (void)res;
    (void)reslen;
    g_map.erase(cmd[1]);
    return RES_OK;
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

// Determine request
static int32_t do_request(
    const uint8_t *req, uint32_t reqlen,
    uint32_t *rescode, uint8_t *res, uint32_t *reslen)
{  
    std::vector<std::string> cmd;
    if (0 != parse_req(req, reqlen, cmd)) {
        msg("bad req");
        return -1;
    }
    if (cmd.size() == 2 && cmd_is(cmd[0], "get"))
        *rescode = do_get(cmd, res, reslen);
    else if (cmd.size() == 3 && cmd_is(cmd[0], "set"))
        *rescode = do_set(cmd, res, reslen);
    else if (cmd.size() == 2 && cmd_is(cmd[0], "del"))
        *rescode = do_del(cmd, res, reslen);
    else {
        // Command not recognized
        *rescode = RES_ERR;
        const char *msg = "Unknown cmd";
        strcpy((char *)res, msg);
        *reslen = strlen(msg);
    }
    return 0;
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

    // Get request and generate response
    uint32_t rescode = 0;
    uint32_t wlen = 0;
    int32_t err = do_request(
        &conn->rbuf[4], len,
        &rescode, &conn->wbuf[4 + 4], &wlen
    );
    if (err) {
        conn->state = STATE_END;
        return false;
    }

    wlen += 4;
    memcpy(&conn->wbuf[0], &wlen, 4);
    memcpy(&conn->wbuf[4], &rescode, 4);
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

static void state_req(Conn *conn) {
    while (try_fill_buffer(conn)) {}
}

static void state_res(Conn *conn) {
    // ** Buffer multiple responses and write once **
    while (try_flush_buffer(conn)) {}
}

// [State machine for client connections]
static void connection_io(Conn *conn) {
    if (conn->state == STATE_REQ)
        state_req(conn);
    else if (conn->state == STATE_RES)
        state_res(conn);
    else
        assert(0);
}

int main() {
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

    std::vector<Conn *> fd2conn;          // Map of fds to client connections
    fd_set_nb(fd);                        // Set to nonblocking
    std::vector<struct pollfd> poll_args; // Poll request arguments - fd, [status of data], ?

    /*  Event loop: General idea is to seach for active fds by polling and operate.
          */
    while (true) {
        poll_args.clear();
        // Listening [socket] fd in first position
        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);
        
        // Connection fds
        for (Conn *conn : fd2conn) {
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
        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), 1000);
        if (rv < 0)
            die("poll");
        
        // Process active connections
        for (size_t i = 1; i < poll_args.size(); i++) {
            if (poll_args[i].revents) {
                Conn *conn = fd2conn[poll_args[i].fd];
                connection_io(conn);
                if (conn->state == STATE_END) {
                    // Destroy
                    fd2conn[conn->fd] = NULL;
                    (void)close(conn->fd);
                    free(conn);
                }
            }
        }

        // Accept new connection if listening fd is active
        if (poll_args[0].revents)
            (void)accept_new_conn(fd2conn, fd);
    }

    return 0;
}