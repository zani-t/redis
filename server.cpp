#include <iostream>
#include <cstdlib>
#include <cstring>

#include <stdint.h>         // ...
#include <errno.h>          // Error handling
#include <unistd.h>         // Read & write functions
#include <arpa/inet.h>      // Internet operations
#include <sys/socket.h>     // ...
#include <netinet/ip.h>     // ...

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d], %s\n", err, msg);
    abort();
}

// Connection test
static void do_something(int connfd) {
    char rbuf[64] = {};
    ssize_t n = read(connfd, rbuf, sizeof(rbuf) - 1);
    if (n < 0) {
        msg("read() error");
        return;
    }

    printf("client says: %s\n", rbuf);
    char wbuf[] = "world";
    write(connfd, wbuf, strlen(wbuf));
}

int main() {
    // Retrieve file desciptor - handler for given type of i/o resource
    // Parameters [assert] IPv4 TCP socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    
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

        // Action - respond to messages
        do_something(connfd);
        // Recycle fd
        close(connfd);
    }

    return 0;
}