#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Darwin ]] || {
  printf 'macOS interpose feasibility requires macOS\n' >&2
  exit 1
}
[[ $(uname -m) == arm64 ]] || {
  printf 'macOS interpose feasibility requires Apple silicon\n' >&2
  exit 1
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../.." && pwd -P)
cd "$repo_root"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-interpose-feasibility.XXXXXX")
fixture_pid=
cleanup() {
  if [[ -n $fixture_pid ]]; then
    kill "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

ready=$work_dir/fixture.json
fixture_log=$work_dir/fixture.jsonl
python3 tests/macos/fixture.py --ready "$ready" --log "$fixture_log" &
fixture_pid=$!
for _ in $(seq 1 100); do
  [[ -s $ready ]] && break
  kill -0 "$fixture_pid" 2>/dev/null || {
    printf 'macOS interpose fixture exited before readiness\n' >&2
    exit 1
  }
  sleep 0.05
done
[[ -s $ready ]] || {
  printf 'macOS interpose fixture did not become ready\n' >&2
  exit 1
}
http_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_port"])' "$ready")
udp_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["udp_port"])' "$ready")

library=$work_dir/libheimdall_probe.dylib
xcrun clang -dynamiclib -arch arm64 -Wall -Wextra -Werror \
  -o "$library" -x c - <<'SOURCE'
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

static connect_fn system_connect = &connect;
static getaddrinfo_fn system_getaddrinfo = &getaddrinfo;

static int heimdall_connect(int socket_fd, const struct sockaddr *address, socklen_t length) {
    int socket_type = 0;
    socklen_t option_length = sizeof(socket_type);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &socket_type, &option_length) == 0 &&
        socket_type == SOCK_STREAM && address != NULL &&
        (address->sa_family == AF_INET || address->sa_family == AF_INET6)) {
        fputs("HEIMDALL_INTERPOSE_TCP\n", stderr);
        errno = ECONNREFUSED;
        return -1;
    }

    return system_connect(socket_fd, address, length);
}

static int heimdall_getaddrinfo(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **result
) {
    if (node != NULL && strcmp(node, "localhost") == 0) {
        fputs("HEIMDALL_INTERPOSE_RESOLVER\n", stderr);
        return EAI_FAIL;
    }

    return system_getaddrinfo(node, service, hints, result);
}

__attribute__((constructor)) static void heimdall_probe_loaded(void) {
    fputs("HEIMDALL_INTERPOSE_LOADED\n", stderr);
}

struct heimdall_interpose_entry {
    const void *replacement;
    const void *replacee;
};

__attribute__((used, section("__DATA,__interpose")))
static const struct heimdall_interpose_entry heimdall_interposers[] = {
    {(const void *)&heimdall_connect, (const void *)&connect},
    {(const void *)&heimdall_getaddrinfo, (const void *)&getaddrinfo},
};
SOURCE

target=$work_dir/network-target
xcrun clang -arch arm64 -Wall -Wextra -Werror -o "$target" -x c - <<'SOURCE'
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int exchange_http(int socket_fd) {
    const char request[] = "GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n";
    char response[4096];
    size_t used = 0;
    if (send(socket_fd, request, sizeof(request) - 1, 0) < 0) return 20;
    while (used < sizeof(response) - 1) {
        ssize_t size = recv(socket_fd, response + used, sizeof(response) - 1 - used, 0);
        if (size < 0) return 21;
        if (size == 0) break;
        used += (size_t)size;
    }
    response[used] = '\0';
    return strstr(response, "heimdall-fixture-ok") == NULL ? 22 : 0;
}

static int tcp_call(const char *host, const char *port) {
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)strtoul(port, NULL, 10));
    if (inet_pton(AF_INET, host, &address.sin_addr) == 1) {
        int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) return 9;
        int result = connect(
            socket_fd,
            (const struct sockaddr *)&address,
            sizeof(address)
        );
        if (result == 0) result = exchange_http(socket_fd);
        else result = 11;
        close(socket_fd);
        return result;
    }

    struct addrinfo hints = {0};
    struct addrinfo *head = NULL;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &head) != 0) return 10;
    int result = 11;
    for (struct addrinfo *item = head; item != NULL; item = item->ai_next) {
        int socket_fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (socket_fd < 0) continue;
        if (connect(socket_fd, item->ai_addr, item->ai_addrlen) == 0) {
            result = exchange_http(socket_fd);
            close(socket_fd);
            break;
        }
        close(socket_fd);
    }
    freeaddrinfo(head);
    return result;
}

static int connectx_call(const char *host, const char *port) {
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)strtoul(port, NULL, 10));
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) return 30;
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) return 31;
    sa_endpoints_t endpoints = {0};
    endpoints.sae_dstaddr = (const struct sockaddr *)&address;
    endpoints.sae_dstaddrlen = sizeof(address);
    int result = connectx(
        socket_fd,
        &endpoints,
        SAE_ASSOCID_ANY,
        0,
        NULL,
        0,
        NULL,
        NULL
    );
    if (result == 0) result = exchange_http(socket_fd);
    else result = 32;
    close(socket_fd);
    return result;
}

static int udp_call(const char *host, const char *port, int connected) {
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)strtoul(port, NULL, 10));
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) return 40;
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) return 41;
    struct timeval timeout = {.tv_sec = 2};
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        close(socket_fd);
        return 42;
    }
    const char request[] = "heimdall-macos-udp";
    ssize_t sent;
    if (connected) {
        if (connect(socket_fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
            close(socket_fd);
            return 43;
        }
        sent = send(socket_fd, request, sizeof(request) - 1, 0);
    } else {
        sent = sendto(
            socket_fd,
            request,
            sizeof(request) - 1,
            0,
            (const struct sockaddr *)&address,
            sizeof(address)
        );
    }
    if (sent != (ssize_t)(sizeof(request) - 1)) {
        close(socket_fd);
        return 44;
    }
    char response[64];
    ssize_t received = recv(socket_fd, response, sizeof(response) - 1, 0);
    close(socket_fd);
    if (received < 0) return 45;
    response[received] = '\0';
    return strcmp(response, "heimdall-macos-udp-ok") == 0 ? 0 : 46;
}

static int resolve_localhost(void) {
    struct addrinfo *result = NULL;
    int status = getaddrinfo("localhost", "80", NULL, &result);
    if (status == 0) freeaddrinfo(result);
    return status == 0 ? 0 : 60;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "non-network") == 0) {
        puts("HEIMDALL_TARGET_OK");
        return 0;
    }
    if (strcmp(argv[1], "tcp") == 0 && argc == 4) return tcp_call(argv[2], argv[3]);
    if (strcmp(argv[1], "connectx") == 0 && argc == 4) return connectx_call(argv[2], argv[3]);
    if (strcmp(argv[1], "udp") == 0 && argc == 4) return udp_call(argv[2], argv[3], 0);
    if (strcmp(argv[1], "udp-connected") == 0 && argc == 4) {
        return udp_call(argv[2], argv[3], 1);
    }
    if (strcmp(argv[1], "resolve") == 0) return resolve_localhost();
    if (strcmp(argv[1], "fork") == 0 && argc == 4) {
        pid_t pid = fork();
        if (pid == 0) _exit(tcp_call(argv[2], argv[3]));
        int status = 0;
        if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) return 50;
        return WEXITSTATUS(status);
    }
    if (strcmp(argv[1], "exec-inherit") == 0 && argc == 5) {
        execl(argv[2], argv[2], "tcp", argv[3], argv[4], (char *)NULL);
        return 51;
    }
    if (strcmp(argv[1], "exec-clear") == 0 && argc == 5) {
        unsetenv("DYLD_INSERT_LIBRARIES");
        unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
        execl(argv[2], argv[2], "tcp", argv[3], argv[4], (char *)NULL);
        return 52;
    }
    return 3;
}
SOURCE

swift_target=$work_dir/network-framework-target
xcrun swiftc -o "$swift_target" - <<'SOURCE'
import Dispatch
import Foundation
import Network
import Darwin

guard CommandLine.arguments.count == 2,
      let rawPort = UInt16(CommandLine.arguments[1]),
      let port = NWEndpoint.Port(rawValue: rawPort) else { exit(2) }
let connection = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
let queue = DispatchQueue(label: "heimdall.interpose.feasibility")
let done = DispatchSemaphore(value: 0)
var result: Int32 = 3
connection.stateUpdateHandler = { state in
    switch state {
    case .ready:
        let bytes = Data("GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n".utf8)
        connection.send(content: bytes, completion: .contentProcessed { error in
            if error != nil { result = 4; done.signal(); return }
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, error in
                if error == nil, let data,
                   String(decoding: data, as: UTF8.self).contains("heimdall-fixture-ok") {
                    result = 0
                } else {
                    result = 5
                }
                done.signal()
            }
        })
    case .failed:
        result = 6
        done.signal()
    case .cancelled:
        if result != 0 { result = 7; done.signal() }
    default:
        break
    }
}
connection.start(queue: queue)
if done.wait(timeout: .now() + 5) == .timedOut { result = 8 }
connection.cancel()
exit(result)
SOURCE

codesign --force --sign - "$library" >/dev/null 2>&1
codesign --force --sign - "$target" >/dev/null 2>&1
codesign --force --sign - "$swift_target" >/dev/null 2>&1
cp "$target" "$work_dir/hardened-target"
codesign --force --sign - --options runtime \
  "$work_dir/hardened-target" >/dev/null 2>&1

case_output=
case_status=0
capture_injected() {
  set +e
  case_output=$(
    DYLD_INSERT_LIBRARIES="$library" \
      DYLD_FORCE_FLAT_NAMESPACE=1 \
      "$@" 2>&1
  )
  case_status=$?
  set -e
}

capture_injected "$target" non-network
[[ $case_status -eq 0 ]] || {
  printf 'ordinary dynamic non-network target failed: %s\n' "$case_status" >&2
  exit 1
}
grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$case_output" || {
  printf 'ordinary dynamic target did not load the injected library\n' >&2
  exit 1
}
grep -Fq 'HEIMDALL_TARGET_OK' <<<"$case_output" || {
  printf 'ordinary dynamic target did not complete\n' >&2
  exit 1
}

capture_injected "$target" tcp 127.0.0.1 "$http_port"
[[ $case_status -ne 0 ]] || {
  printf 'ordinary dynamic TCP escaped the interposed connect hook\n' >&2
  exit 1
}
grep -Fq 'HEIMDALL_INTERPOSE_TCP' <<<"$case_output" || {
  printf 'ordinary dynamic TCP did not reach the interposed connect hook\n' >&2
  exit 1
}

capture_injected "$target" resolve
[[ $case_status -ne 0 ]] || {
  printf 'ordinary libc resolver escaped the interposed getaddrinfo hook\n' >&2
  exit 1
}
grep -Fq 'HEIMDALL_INTERPOSE_RESOLVER' <<<"$case_output" || {
  printf 'ordinary libc resolver did not reach the interposed getaddrinfo hook\n' >&2
  exit 1
}

capture_injected "$target" fork 127.0.0.1 "$http_port"
[[ $case_status -ne 0 ]] || {
  printf 'forked dynamic TCP escaped inherited interposition\n' >&2
  exit 1
}
grep -Fq 'HEIMDALL_INTERPOSE_TCP' <<<"$case_output" || {
  printf 'forked dynamic TCP did not retain interposition\n' >&2
  exit 1
}

capture_injected "$target" exec-inherit "$target" 127.0.0.1 "$http_port"
[[ $case_status -ne 0 ]] || {
  printf 'exec with inherited loader state escaped interposition\n' >&2
  exit 1
}
grep -Fq 'HEIMDALL_INTERPOSE_TCP' <<<"$case_output" || {
  printf 'exec with inherited loader state did not retain interposition\n' >&2
  exit 1
}

capture_injected "$work_dir/hardened-target" tcp 127.0.0.1 "$http_port"
[[ $case_status -eq 0 ]] || {
  printf 'Hardened Runtime boundary changed: target status %s\n' "$case_status" >&2
  exit 1
}
if grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$case_output"; then
  printf 'Hardened Runtime target unexpectedly loaded the injected library\n' >&2
  exit 1
fi

capture_injected /usr/bin/curl --fail --silent "http://127.0.0.1:$http_port/"
[[ $case_status -eq 0 ]] || {
  printf 'SIP curl boundary changed: target status %s\n' "$case_status" >&2
  exit 1
}
if grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$case_output"; then
  printf 'SIP-protected curl unexpectedly loaded the injected library\n' >&2
  exit 1
fi

capture_injected "$target" exec-clear "$target" 127.0.0.1 "$http_port"
[[ $case_status -eq 0 ]] || {
  printf 'loader-state removal boundary changed: target status %s\n' "$case_status" >&2
  exit 1
}
if grep -Fq 'HEIMDALL_INTERPOSE_TCP' <<<"$case_output"; then
  printf 'exec after loader-state removal unexpectedly retained the TCP hook\n' >&2
  exit 1
fi

capture_injected "$target" connectx 127.0.0.1 "$http_port"
[[ $case_status -eq 0 ]] || {
  printf 'connectx boundary changed: target status %s\n' "$case_status" >&2
  exit 1
}
grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$case_output" || {
  printf 'connectx target did not load the probe\n' >&2
  exit 1
}
if grep -Fq 'HEIMDALL_INTERPOSE_TCP' <<<"$case_output"; then
  printf 'connectx unexpectedly used the connect hook\n' >&2
  exit 1
fi

capture_injected "$swift_target" "$http_port"
[[ $case_status -eq 0 ]] || {
  printf 'Network.framework boundary changed: target status %s\n' "$case_status" >&2
  exit 1
}
grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$case_output" || {
  printf 'Network.framework target did not load the probe\n' >&2
  exit 1
}
if grep -Fq 'HEIMDALL_INTERPOSE_TCP' <<<"$case_output"; then
  printf 'Network.framework unexpectedly used the connect hook\n' >&2
  exit 1
fi

for udp_mode in udp udp-connected; do
  capture_injected "$target" "$udp_mode" 127.0.0.1 "$udp_port"
  [[ $case_status -eq 0 ]] || {
    printf '%s boundary changed: target status %s\n' "$udp_mode" "$case_status" >&2
    exit 1
  }
  grep -Fq 'HEIMDALL_INTERPOSE_LOADED' <<<"$case_output" || {
    printf '%s target did not load the probe\n' "$udp_mode" >&2
    exit 1
  }
  if grep -Fq 'HEIMDALL_INTERPOSE_TCP' <<<"$case_output"; then
    printf '%s unexpectedly entered the TCP hook\n' "$udp_mode" >&2
    exit 1
  fi
done

background_marker=$work_dir/background-response
capture_injected /bin/sh -c \
  "(sleep 1; /usr/bin/curl --fail --silent \"\$2\" >\"\$1\") >/dev/null 2>&1 &" \
  sh "$background_marker" "http://127.0.0.1:$http_port/"
[[ $case_status -eq 0 ]] || {
  printf 'SIP shell background boundary changed: target status %s\n' "$case_status" >&2
  exit 1
}
[[ ! -e $background_marker ]] || {
  printf 'background marker appeared before the wrapper returned\n' >&2
  exit 1
}
for _ in $(seq 1 100); do
  [[ -s $background_marker ]] && break
  sleep 0.05
done
grep -Fq 'heimdall-fixture-ok' "$background_marker" || {
  printf 'background descendant did not outlive the wrapper and connect directly\n' >&2
  exit 1
}

printf 'macOS interpose feasibility boundary OK '
printf '(ordinary_tcp=interposed resolver=interposed fork=interposed exec=interposed '
printf 'hardened=bypass sip=bypass loader_clear=bypass connectx=bypass '
printf 'network_framework=bypass udp=bypass background_descendant=bypass)\n'
