// #include "utils.hpp"
#include <iostream>
#include <cassert>
#include <cstdlib>
#include <cstring>

// #include <stdint.h>         // ...
#include <errno.h>          // Error handling
#include <fcntl.h>          // File descriptor control
#include <unistd.h>         // Read & write functions
#include <arpa/inet.h>      // Internet operations
// #include <sys/socket.h>     // ...
// #include <netinet/ip.h>     // ...

// EXPORT
const size_t k_max_msg = 4096;

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d], %s\n", err, msg);
    abort();
}

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

int main() {
    // Retrieve file desciptor - handler for given type of i/o resource
    // Parameters [assert] IPv4 TCP socket
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

    // Loop
    while (true) {
        // Accept fd and return connection socket
        struct sockaddr_in client_addr = {};
        socklen_t socklen = sizeof(client_addr);
        int connfd = accept(fd, (struct sockaddr *)&client_addr, &socklen);
        // Error handling - reiterate
        if (connfd < 0)
            continue;

        // Handle one request until connection is lost
        while (true) {
            int32_t err = one_request(connfd);
            if (err)
                break;
        }
        // Recycle fd
        close(connfd);
    }

    return 0;
}