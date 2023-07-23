#include <iostream>
#include <cstring>

#include <errno.h>          // Error handling
#include <unistd.h>         // Read & write functions
#include <arpa/inet.h>      // Internet operations

// DEFINE IN HEADER/SEPARATE FILE
static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d], %s\n", err, msg);
    abort();
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
    
    // Action - write message
    char msg[] = "hello";
    write(fd, msg, strlen(msg));

    // Get response
    char rbuf[64] = {};
    ssize_t n = read(fd, rbuf, sizeof(rbuf) - 1);
    if (n < 0)
        die("read");
    
    printf("server says: %s\n", rbuf);
    close(fd);

    return 0;
}