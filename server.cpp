// #include "utils.hpp"
#include <iostream>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>
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

// ...
enum {
    STATE_REQ = 0,
    STATE_RES = 1,
    STATE_END = 2,
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

// EXPORT
// Read n bytes from kernel [through several requests]
static int32_t read_full(int fd, char *buf, size_t n) {
    while (n > 0) {
        ssize_t rv = read(fd, buf, n);
        // Error or unexpected EOF
        if (rv <= 0)
            return -1;

        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

// EXPORT
// Write n bytes [through several requests]
static int32_t write_all(int fd, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t rv = write(fd, buf, n);
        if (rv <= 0)
            return -1;
        
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
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
    variable-length message itself.  */
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
}

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

// [State machine for client connections]
static void connection_io(Conn *conn) {
    if (conn->state == STATE_REQ)
        state_req(conn);
    else if (conn->state == STATE_RES)
        state_res(conn);
    else
        assert(0);
}

static void state_req(Conn *conn) {
    while (try_fill_buffer(conn)) {}
}

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

static bool try_one_request(Conn *conn) {
    // Parse buffer request

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

    printf("client says: %.*s\n", len, &conn->rbuf[4]);
    memcpy(&conn->wbuf[0], &len, 4);
    memcpy(&conn->wbuf[4], &conn->rbuf[4], len);
    conn->wbuf_size = 4 + len;

    // Remove request from buffer
    size_t remain = conn->rbuf_size - 4 - len;
    if (remain)
        memmove(conn->rbuf, &conn->rbuf[4 + len], remain);
    conn->rbuf_size = remain;

    // Change state
    conn->state = STATE_RES;
    state_res(conn);

    return (conn->state == STATE_REQ);
}

static void state_res(Conn *conn) {
    while (try_flush_buffer(conn)) {}
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