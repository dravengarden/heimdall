#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define HEIMDALL_ACTIVE "HEIMDALL_INTERPOSE_ACTIVE"
#define HEIMDALL_PORT "HEIMDALL_INTERPOSE_PORT"
#define HEIMDALL_TOKEN "HEIMDALL_INTERPOSE_TOKEN"
#define HEIMDALL_DNS "HEIMDALL_INTERPOSE_DNS"
#define HEIMDALL_MAPPING_COUNT 128
#define HEIMDALL_HOST_MAX 253
#define HEIMDALL_TOKEN_MAX 128
#define SOCKS_VERSION 5
#define SOCKS_USERNAME_PASSWORD 2
#define SOCKS_AUTH_VERSION 1
#define SOCKS_CONNECT 1

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*sendto_fn)(
    int, const void *, size_t, int, const struct sockaddr *, socklen_t
);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
#if !defined(__APPLE__)
#if defined(__GLIBC__)
typedef int heimdall_sendmmsg_flags;
#else
// Why: musl declares sendmmsg flags as unsigned while glibc uses int. The
// argument has the same ABI width, but the wrapper must match each header's
// declaration exactly so release cross-builds remain warning- and error-free.
typedef unsigned int heimdall_sendmmsg_flags;
#endif
typedef int (*sendmmsg_fn)(
    int, struct mmsghdr *, unsigned int, heimdall_sendmmsg_flags
);
#endif

struct host_mapping {
    int used;
    char host[HEIMDALL_HOST_MAX + 1];
};

static int initialized;
static int enabled;
static int fake_dns;
static uint16_t proxy_port;
static size_t token_length;
static char token[HEIMDALL_TOKEN_MAX + 1];
static struct host_mapping mappings[HEIMDALL_MAPPING_COUNT];
static unsigned char mappings_lock;
static _Thread_local int inside_hook;

#if defined(__APPLE__)
static connect_fn real_connect = &connect;
static getaddrinfo_fn real_getaddrinfo = &getaddrinfo;
static send_fn real_send = &send;
static sendto_fn real_sendto = &sendto;
static sendmsg_fn real_sendmsg = &sendmsg;
#else
static connect_fn real_connect;
static getaddrinfo_fn real_getaddrinfo;
static send_fn real_send;
static sendto_fn real_sendto;
static sendmsg_fn real_sendmsg;
static sendmmsg_fn real_sendmmsg;
#endif

static size_t bounded_length(const char *value, size_t maximum) {
    size_t length = 0;
    if (value == NULL) return 0;
    while (length <= maximum && value[length] != '\0') length++;
    return length;
}

static int equal_string(const char *left, const char *right) {
    size_t index = 0;
    if (left == NULL || right == NULL) return 0;
    while (left[index] != '\0' && left[index] == right[index]) index++;
    return left[index] == '\0' && right[index] == '\0';
}

static void copy_bytes(void *destination, const void *source, size_t length) {
    unsigned char *out = destination;
    const unsigned char *in = source;
    for (size_t index = 0; index < length; index++) out[index] = in[index];
}

static void lock_mappings(void) {
    while (__atomic_test_and_set(&mappings_lock, __ATOMIC_ACQUIRE)) {}
}

static void unlock_mappings(void) {
    __atomic_clear(&mappings_lock, __ATOMIC_RELEASE);
}

static uint32_t hash_host(const char *host) {
    uint32_t hash = 2166136261u;
    for (size_t index = 0; host[index] != '\0'; index++) {
        hash ^= (unsigned char)host[index];
        hash *= 16777619u;
    }
    return hash;
}

static int parse_port(const char *value, uint16_t *result) {
    unsigned long port = 0;
    size_t length = bounded_length(value, 5);
    if (length == 0 || length > 5) return 0;
    for (size_t index = 0; index < length; index++) {
        if (value[index] < '0' || value[index] > '9') return 0;
        port = port * 10 + (unsigned long)(value[index] - '0');
    }
    if (port == 0 || port > 65535) return 0;
    *result = (uint16_t)port;
    return 1;
}

static void initialize(void) {
    if (__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) return;
    const char *active = getenv(HEIMDALL_ACTIVE);
    const char *port = getenv(HEIMDALL_PORT);
    const char *secret = getenv(HEIMDALL_TOKEN);
    const char *dns = getenv(HEIMDALL_DNS);
    size_t secret_length = bounded_length(secret, HEIMDALL_TOKEN_MAX);
    uint16_t parsed_port = 0;
    if (equal_string(active, "1") && parse_port(port, &parsed_port) &&
        secret_length > 0 && secret_length <= HEIMDALL_TOKEN_MAX &&
        (equal_string(dns, "fake") || equal_string(dns, "system"))) {
        proxy_port = parsed_port;
        token_length = secret_length;
        copy_bytes(token, secret, secret_length + 1);
        fake_dns = equal_string(dns, "fake");
        enabled = 1;
    }
    __atomic_store_n(&initialized, 1, __ATOMIC_RELEASE);
}

__attribute__((constructor)) static void heimdall_interpose_initialize(void) {
    initialize();
}

#if !defined(__APPLE__)
static void resolve_originals(void) {
    if (real_connect == NULL) {
        *(void **)(&real_connect) = dlsym(RTLD_NEXT, "connect");
    }
    if (real_getaddrinfo == NULL) {
        *(void **)(&real_getaddrinfo) = dlsym(RTLD_NEXT, "getaddrinfo");
    }
    if (real_send == NULL) {
        *(void **)(&real_send) = dlsym(RTLD_NEXT, "send");
    }
    if (real_sendto == NULL) {
        *(void **)(&real_sendto) = dlsym(RTLD_NEXT, "sendto");
    }
    if (real_sendmsg == NULL) {
        *(void **)(&real_sendmsg) = dlsym(RTLD_NEXT, "sendmsg");
    }
    if (real_sendmmsg == NULL) {
        *(void **)(&real_sendmmsg) = dlsym(RTLD_NEXT, "sendmmsg");
    }
}
#endif

static int is_network_datagram(int socket_fd) {
    int socket_type = 0;
    socklen_t option_length = sizeof(socket_type);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &socket_type, &option_length) != 0 ||
        socket_type != SOCK_DGRAM) {
        return 0;
    }
    struct sockaddr_storage local = {0};
    socklen_t local_length = sizeof(local);
    if (getsockname(socket_fd, (struct sockaddr *)&local, &local_length) != 0) {
        // Why: an injected call whose datagram family cannot be established
        // must not silently bypass a configuration that rejects all UDP.
        return 1;
    }
    return local.ss_family == AF_INET || local.ss_family == AF_INET6;
}

static int reject_network_datagram(int socket_fd) {
    if (inside_hook || !is_network_datagram(socket_fd)) return 0;
    errno = EACCES;
    return 1;
}

static int mapping_for_host(const char *host) {
    size_t length = bounded_length(host, HEIMDALL_HOST_MAX);
    if (length == 0 || length > HEIMDALL_HOST_MAX) return -1;
    uint32_t first = hash_host(host) % HEIMDALL_MAPPING_COUNT;
    int available = -1;
    lock_mappings();
    for (uint32_t offset = 0; offset < HEIMDALL_MAPPING_COUNT; offset++) {
        uint32_t slot = (first + offset) % HEIMDALL_MAPPING_COUNT;
        if (mappings[slot].used && equal_string(mappings[slot].host, host)) {
            unlock_mappings();
            return (int)slot;
        }
        if (!mappings[slot].used && available < 0) available = (int)slot;
    }
    if (available >= 0) {
        mappings[available].used = 1;
        copy_bytes(mappings[available].host, host, length + 1);
    }
    unlock_mappings();
    return available;
}

static int host_for_slot(int slot, char output[HEIMDALL_HOST_MAX + 1]) {
    if (slot < 0 || slot >= HEIMDALL_MAPPING_COUNT) return 0;
    lock_mappings();
    if (!mappings[slot].used) {
        unlock_mappings();
        return 0;
    }
    copy_bytes(output, mappings[slot].host, HEIMDALL_HOST_MAX + 1);
    unlock_mappings();
    return 1;
}

static void fake_ipv4_for_slot(int slot, struct in_addr *address) {
    uint32_t value = (198u << 24) | (18u << 16) | (uint32_t)(slot + 1);
    address->s_addr = htonl(value);
}

static void fake_ipv6_for_slot(int slot, struct in6_addr *address) {
    for (size_t index = 0; index < sizeof(address->s6_addr); index++) {
        address->s6_addr[index] = 0;
    }
    address->s6_addr[0] = 0xfd;
    address->s6_addr[12] = 0x48;
    address->s6_addr[13] = 0x4d;
    address->s6_addr[15] = (unsigned char)(slot + 1);
}

static int slot_for_address(const struct sockaddr *address) {
    if (address->sa_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        uint32_t value = ntohl(ipv4->sin_addr.s_addr);
        if ((value >> 16) != ((198u << 8) | 18u)) return -1;
        uint32_t slot = value & 0xffffu;
        return slot >= 1 && slot <= HEIMDALL_MAPPING_COUNT ? (int)slot - 1 : -1;
    }
    if (address->sa_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        const unsigned char *bytes = ipv6->sin6_addr.s6_addr;
        if (bytes[0] != 0xfd || bytes[12] != 0x48 || bytes[13] != 0x4d ||
            bytes[14] != 0 || bytes[15] == 0 || bytes[15] > HEIMDALL_MAPPING_COUNT) {
            return -1;
        }
        for (size_t index = 1; index < 12; index++) {
            if (bytes[index] != 0) return -1;
        }
        return (int)bytes[15] - 1;
    }
    return -1;
}

static uint16_t destination_port(const struct sockaddr *address) {
    if (address->sa_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)address)->sin_port);
    }
    return ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
}

static int write_all(int socket_fd, const unsigned char *payload, size_t length) {
    size_t written = 0;
    while (written < length) {
#if defined(__APPLE__)
        ssize_t count = send(socket_fd, payload + written, length - written, 0);
#else
        ssize_t count = send(socket_fd, payload + written, length - written, MSG_NOSIGNAL);
#endif
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        written += (size_t)count;
    }
    return 1;
}

static int read_all(int socket_fd, unsigned char *payload, size_t length) {
    size_t read_count = 0;
    while (read_count < length) {
        ssize_t count = recv(socket_fd, payload + read_count, length - read_count, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        read_count += (size_t)count;
    }
    return 1;
}

static int socks_authenticate(int socket_fd) {
    const unsigned char greeting[] = {SOCKS_VERSION, 1, SOCKS_USERNAME_PASSWORD};
    unsigned char response[2];
    if (!write_all(socket_fd, greeting, sizeof(greeting)) ||
        !read_all(socket_fd, response, sizeof(response)) ||
        response[0] != SOCKS_VERSION || response[1] != SOCKS_USERNAME_PASSWORD) {
        return 0;
    }
    static const unsigned char username[] = "heimdall";
    unsigned char auth[3 + sizeof(username) - 1 + HEIMDALL_TOKEN_MAX];
    size_t cursor = 0;
    auth[cursor++] = SOCKS_AUTH_VERSION;
    auth[cursor++] = (unsigned char)(sizeof(username) - 1);
    copy_bytes(auth + cursor, username, sizeof(username) - 1);
    cursor += sizeof(username) - 1;
    auth[cursor++] = (unsigned char)token_length;
    copy_bytes(auth + cursor, token, token_length);
    cursor += token_length;
    if (!write_all(socket_fd, auth, cursor) ||
        !read_all(socket_fd, response, sizeof(response)) ||
        response[0] != SOCKS_AUTH_VERSION || response[1] != 0) {
        return 0;
    }
    return 1;
}

static int socks_connect(int socket_fd, const struct sockaddr *destination) {
    unsigned char request[4 + 1 + HEIMDALL_HOST_MAX + 16 + 2];
    size_t cursor = 0;
    char host[HEIMDALL_HOST_MAX + 1] = {0};
    int slot = slot_for_address(destination);
    request[cursor++] = SOCKS_VERSION;
    request[cursor++] = SOCKS_CONNECT;
    request[cursor++] = 0;
    if (slot >= 0 && host_for_slot(slot, host)) {
        size_t length = bounded_length(host, HEIMDALL_HOST_MAX);
        request[cursor++] = 3;
        request[cursor++] = (unsigned char)length;
        copy_bytes(request + cursor, host, length);
        cursor += length;
    } else if (destination->sa_family == AF_INET) {
        request[cursor++] = 1;
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)destination;
        copy_bytes(request + cursor, &ipv4->sin_addr, 4);
        cursor += 4;
    } else {
        request[cursor++] = 4;
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)destination;
        copy_bytes(request + cursor, &ipv6->sin6_addr, 16);
        cursor += 16;
    }
    uint16_t port = htons(destination_port(destination));
    copy_bytes(request + cursor, &port, sizeof(port));
    cursor += sizeof(port);
    if (!write_all(socket_fd, request, cursor)) return 0;

    unsigned char response[4];
    if (!read_all(socket_fd, response, sizeof(response)) ||
        response[0] != SOCKS_VERSION || response[1] != 0 || response[2] != 0) {
        return 0;
    }
    size_t tail = 0;
    if (response[3] == 1) tail = 4 + 2;
    else if (response[3] == 4) tail = 16 + 2;
    else if (response[3] == 3) {
        unsigned char length = 0;
        if (!read_all(socket_fd, &length, 1)) return 0;
        tail = (size_t)length + 2;
    } else return 0;
    unsigned char discard[257];
    return tail <= sizeof(discard) && read_all(socket_fd, discard, tail);
}

static int heimdall_connect(int socket_fd, const struct sockaddr *address, socklen_t length) {
    initialize();
#if !defined(__APPLE__)
    resolve_originals();
#endif
    if (real_connect == NULL) {
        errno = EIO;
        return -1;
    }
    if (inside_hook || address == NULL ||
        (address->sa_family != AF_INET && address->sa_family != AF_INET6)) {
        return real_connect(socket_fd, address, length);
    }
    socklen_t minimum_length = address->sa_family == AF_INET
        ? (socklen_t)sizeof(struct sockaddr_in)
        : (socklen_t)sizeof(struct sockaddr_in6);
    if (length < minimum_length) return real_connect(socket_fd, address, length);
    int socket_type = 0;
    socklen_t option_length = sizeof(socket_type);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &socket_type, &option_length) != 0) {
        return real_connect(socket_fd, address, length);
    }
    if (socket_type == SOCK_DGRAM) {
        errno = EACCES;
        return -1;
    }
    if (socket_type != SOCK_STREAM) return real_connect(socket_fd, address, length);
    if (!enabled) {
        errno = ECONNREFUSED;
        return -1;
    }

    inside_hook = 1;
    int flags = fcntl(socket_fd, F_GETFL, 0);
    struct timeval original_send_timeout = {0};
    struct timeval original_receive_timeout = {0};
    socklen_t send_timeout_length = sizeof(original_send_timeout);
    socklen_t receive_timeout_length = sizeof(original_receive_timeout);
    int restore_send_timeout = getsockopt(
        socket_fd, SOL_SOCKET, SO_SNDTIMEO, &original_send_timeout, &send_timeout_length
    ) == 0;
    int restore_receive_timeout = getsockopt(
        socket_fd, SOL_SOCKET, SO_RCVTIMEO, &original_receive_timeout, &receive_timeout_length
    ) == 0;
    if (flags >= 0 && (flags & O_NONBLOCK) != 0) {
        (void)fcntl(socket_fd, F_SETFL, flags & ~O_NONBLOCK);
    }
#if defined(__APPLE__)
    int original_no_sigpipe = 0;
    socklen_t no_sigpipe_length = sizeof(original_no_sigpipe);
    int restore_no_sigpipe = getsockopt(
        socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &original_no_sigpipe, &no_sigpipe_length
    ) == 0;
    int no_sigpipe = 1;
    (void)setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
    struct timeval timeout = {.tv_sec = 15, .tv_usec = 0};
    (void)setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in proxy = {0};
#if defined(__APPLE__)
    proxy.sin_len = sizeof(proxy);
#endif
    proxy.sin_family = AF_INET;
    proxy.sin_port = htons(proxy_port);
    proxy.sin_addr.s_addr = htonl(0x7f000001u);
    int result = real_connect(socket_fd, (const struct sockaddr *)&proxy, sizeof(proxy));
    if (result == 0) {
        result = socks_authenticate(socket_fd) && socks_connect(socket_fd, address) ? 0 : -1;
    }
    int operation_errno = errno;
    if (restore_send_timeout) {
        (void)setsockopt(
            socket_fd, SOL_SOCKET, SO_SNDTIMEO,
            &original_send_timeout, send_timeout_length
        );
    }
    if (restore_receive_timeout) {
        (void)setsockopt(
            socket_fd, SOL_SOCKET, SO_RCVTIMEO,
            &original_receive_timeout, receive_timeout_length
        );
    }
#if defined(__APPLE__)
    if (restore_no_sigpipe) {
        (void)setsockopt(
            socket_fd, SOL_SOCKET, SO_NOSIGPIPE,
            &original_no_sigpipe, no_sigpipe_length
        );
    }
#endif
    if (flags >= 0 && (flags & O_NONBLOCK) != 0) {
        (void)fcntl(socket_fd, F_SETFL, flags);
    }
    inside_hook = 0;
    if (result != 0) {
        (void)shutdown(socket_fd, SHUT_RDWR);
        errno = ECONNREFUSED;
        return -1;
    }
    errno = operation_errno;
    return 0;
}

static int heimdall_getaddrinfo(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **result
) {
    initialize();
#if !defined(__APPLE__)
    resolve_originals();
#endif
    if (real_getaddrinfo == NULL) return EAI_FAIL;
    if (inside_hook || node == NULL || !fake_dns ||
        (hints != NULL && (hints->ai_flags & AI_NUMERICHOST) != 0) ||
        (hints != NULL && hints->ai_family != AF_UNSPEC &&
         hints->ai_family != AF_INET && hints->ai_family != AF_INET6)) {
        return real_getaddrinfo(node, service, hints, result);
    }
    struct in_addr numeric_v4;
    struct in6_addr numeric_v6;
    if (inet_pton(AF_INET, node, &numeric_v4) == 1 || inet_pton(AF_INET6, node, &numeric_v6) == 1) {
        return real_getaddrinfo(node, service, hints, result);
    }
    if (!enabled) return EAI_FAIL;
    int slot = mapping_for_host(node);
    if (slot < 0) return EAI_MEMORY;

    char numeric[INET6_ADDRSTRLEN];
    struct addrinfo numeric_hints = {0};
    if (hints != NULL) numeric_hints = *hints;
    int family = numeric_hints.ai_family == AF_INET6 ? AF_INET6 : AF_INET;
    numeric_hints.ai_family = family;
    numeric_hints.ai_flags |= AI_NUMERICHOST;
    const void *address;
    if (family == AF_INET6) {
        fake_ipv6_for_slot(slot, &numeric_v6);
        address = &numeric_v6;
    } else {
        fake_ipv4_for_slot(slot, &numeric_v4);
        address = &numeric_v4;
    }
    if (inet_ntop(family, address, numeric, sizeof(numeric)) == NULL) return EAI_FAIL;
    inside_hook = 1;
    int status = real_getaddrinfo(numeric, service, &numeric_hints, result);
    inside_hook = 0;
    return status;
}

static ssize_t heimdall_send(int socket_fd, const void *buffer, size_t length, int flags) {
    initialize();
#if !defined(__APPLE__)
    resolve_originals();
#endif
    if (real_send == NULL) {
        errno = EIO;
        return -1;
    }
    if (reject_network_datagram(socket_fd)) return -1;
    return real_send(socket_fd, buffer, length, flags);
}

static ssize_t heimdall_sendto(
    int socket_fd,
    const void *buffer,
    size_t length,
    int flags,
    const struct sockaddr *destination,
    socklen_t destination_length
) {
    initialize();
#if !defined(__APPLE__)
    resolve_originals();
#endif
    if (real_sendto == NULL) {
        errno = EIO;
        return -1;
    }
    if (reject_network_datagram(socket_fd)) return -1;
    return real_sendto(
        socket_fd, buffer, length, flags, destination, destination_length
    );
}

static ssize_t heimdall_sendmsg(int socket_fd, const struct msghdr *message, int flags) {
    initialize();
#if !defined(__APPLE__)
    resolve_originals();
#endif
    if (real_sendmsg == NULL) {
        errno = EIO;
        return -1;
    }
    if (reject_network_datagram(socket_fd)) return -1;
    return real_sendmsg(socket_fd, message, flags);
}

#if !defined(__APPLE__)
static int heimdall_sendmmsg(
    int socket_fd,
    struct mmsghdr *messages,
    unsigned int count,
    heimdall_sendmmsg_flags flags
) {
    initialize();
    resolve_originals();
    if (real_sendmmsg == NULL) {
        errno = EIO;
        return -1;
    }
    if (reject_network_datagram(socket_fd)) return -1;
    return real_sendmmsg(socket_fd, messages, count, flags);
}
#endif

#if defined(__APPLE__)
struct heimdall_interpose_entry {
    const void *replacement;
    const void *replacee;
};

__attribute__((used, section("__DATA,__interpose")))
static const struct heimdall_interpose_entry heimdall_interposers[] = {
    {(const void *)&heimdall_connect, (const void *)&connect},
    {(const void *)&heimdall_getaddrinfo, (const void *)&getaddrinfo},
    {(const void *)&heimdall_send, (const void *)&send},
    {(const void *)&heimdall_sendto, (const void *)&sendto},
    {(const void *)&heimdall_sendmsg, (const void *)&sendmsg},
};
#else
__attribute__((visibility("default")))
int connect(int socket_fd, const struct sockaddr *address, socklen_t length) {
    return heimdall_connect(socket_fd, address, length);
}

__attribute__((visibility("default")))
int getaddrinfo(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **result
) {
    return heimdall_getaddrinfo(node, service, hints, result);
}

__attribute__((visibility("default")))
ssize_t send(int socket_fd, const void *buffer, size_t length, int flags) {
    return heimdall_send(socket_fd, buffer, length, flags);
}

__attribute__((visibility("default")))
ssize_t sendto(
    int socket_fd,
    const void *buffer,
    size_t length,
    int flags,
    const struct sockaddr *destination,
    socklen_t destination_length
) {
    return heimdall_sendto(
        socket_fd, buffer, length, flags, destination, destination_length
    );
}

__attribute__((visibility("default")))
ssize_t sendmsg(int socket_fd, const struct msghdr *message, int flags) {
    return heimdall_sendmsg(socket_fd, message, flags);
}

__attribute__((visibility("default")))
int sendmmsg(
    int socket_fd,
    struct mmsghdr *messages,
    unsigned int count,
    heimdall_sendmmsg_flags flags
) {
    return heimdall_sendmmsg(socket_fd, messages, count, flags);
}
#endif
