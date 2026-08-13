#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void fail(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

int main(void) {
    const char *payloads[] = {"batch-one", "batch-two"};
    const char *expected[] = {"udp-v4:batch-one", "udp-v4-alt:batch-two"};
    const int ports[] = {18082, 18084};
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) fail("socket");

    struct timeval timeout = {.tv_sec = 5};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        fail("setsockopt");

    struct sockaddr_in targets[2] = {0};
    struct iovec send_iov[2] = {0};
    struct mmsghdr send_messages[2] = {0};
    for (size_t i = 0; i < 2; i++) {
        targets[i].sin_family = AF_INET;
        targets[i].sin_port = htons(ports[i]);
        targets[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        send_iov[i].iov_base = (void *)payloads[i];
        send_iov[i].iov_len = strlen(payloads[i]);
        send_messages[i].msg_hdr.msg_name = &targets[i];
        send_messages[i].msg_hdr.msg_namelen = sizeof(targets[i]);
        send_messages[i].msg_hdr.msg_iov = &send_iov[i];
        send_messages[i].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(fd, send_messages, 2, 0) != 2) fail("sendmmsg");

    char buffers[2][64] = {{0}};
    struct sockaddr_in sources[2] = {0};
    struct iovec receive_iov[2] = {0};
    struct mmsghdr receive_messages[2] = {0};
    for (size_t i = 0; i < 2; i++) {
        receive_iov[i].iov_base = buffers[i];
        receive_iov[i].iov_len = sizeof(buffers[i]) - 1;
        receive_messages[i].msg_hdr.msg_name = &sources[i];
        receive_messages[i].msg_hdr.msg_namelen = sizeof(sources[i]);
        receive_messages[i].msg_hdr.msg_iov = &receive_iov[i];
        receive_messages[i].msg_hdr.msg_iovlen = 1;
    }
    int received = recvmmsg(fd, receive_messages, 2, 0, NULL);
    if (received != 2) fail("recvmmsg");

    int matched[2] = {0};
    for (int i = 0; i < received; i++) {
        buffers[i][receive_messages[i].msg_len] = '\0';
        for (size_t candidate = 0; candidate < 2; candidate++) {
            if (strcmp(buffers[i], expected[candidate]) == 0 &&
                ntohs(sources[i].sin_port) == ports[candidate] &&
                sources[i].sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
                matched[candidate] = 1;
            }
        }
    }
    close(fd);
    if (!matched[0] || !matched[1]) {
        fputs("batch response or restored source mismatch\n", stderr);
        return EXIT_FAILURE;
    }
    puts("udp-batch-ok");
    return EXIT_SUCCESS;
}
