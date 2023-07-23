// #include "utils.hpp"
#include <iostream>
#include <cassert>
#include <cstdlib>
#include <cstring>

#include <stdint.h>         // ...
#include <errno.h>          // Error handling
#include <unistd.h>         // Read & write functions
#include <arpa/inet.h>      // Internet operations
#include <sys/socket.h>     // ...
#include <netinet/ip.h>     // ...

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

static int32_t query(int fd, const char *text) {
    uint32_t len = (uint32_t)strlen(text);
    if (len > k_max_msg)
        return -1;
    
    // Create header & copy request body
    char wbuf[4 + k_max_msg];
    memcpy(wbuf, &len, 4);
    memcpy(&wbuf[4], text, len);
    if (int32_t err = write_all(fd, wbuf, 4 + len))
        return err;
    
    // Get header value
    char rbuf[4 + k_max_msg + 1];
    errno = 0;
    int32_t err = read_full(fd, rbuf, 4);
    if (err) {
        if (errno == 0)
            msg("EOF");
        else
            msg("read() error (head)");
        return err;
    }

    // Set header
    memcpy(&len, rbuf, 4);
    if (len > k_max_msg) {
        msg("too long");
        return -1;
    }

    // Read request body
    err = read_full(fd, &rbuf[4], len);
    if (err) {
        msg("read() error (body)");
        return err;
    }

    // Action - read request
    rbuf[4 + len] = '\0';
    printf("server says: %s\n", &rbuf[4]);
    return 0;
}

int main() {
    // Retrieve file desciptor
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        die("socket()");

    // Bind to IPv4 address
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    // [Convert from network to host byte order] - port 1234 & localhost
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
    int rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rv)
        die("connect");
    
    // Action - send three requests
    int32_t err = query(fd, "hello1");
    if (err)
        goto L_DONE;
    err = query(fd, "hello2");
    if (err)
        goto L_DONE;
    err = query(fd, "hello3");
    if (err)
        goto L_DONE;

    L_DONE:
    close(fd);
    return 0;
}