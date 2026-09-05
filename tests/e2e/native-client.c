// SPDX-License-Identifier: GPL-3.0-only
// A small static, runner-native traffic generator for foreign-architecture E2E.

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s tcp IPV4 PORT TIMEOUT_MS\n"
            "       %s udp IPV4 PORT SOURCE_PORT TIMEOUT_MS PAYLOAD\n",
            program, program);
}

static int parse_number(const char *text, unsigned long maximum,
                        unsigned long *value) {
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || *text == '\0' || *text == '-') {
        return -1;
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
        parsed > maximum) {
        return -1;
    }
    *value = parsed;
    return 0;
}

static int make_address(const char *text, unsigned long port,
                        struct sockaddr_in *address) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((uint16_t)port);
    return inet_pton(AF_INET, text, &address->sin_addr) == 1 ? 0 : -1;
}

static int set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
}

static int wait_for_socket(int descriptor, short events, int timeout_ms) {
    struct pollfd poll_descriptor = {
        .fd = descriptor,
        .events = events,
        .revents = 0,
    };
    int result;

    do {
        result = poll(&poll_descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) {
        if (result == 0) {
            errno = ETIMEDOUT;
        }
        return -1;
    }
    if ((poll_descriptor.revents & events) != 0) {
        return 0;
    }
    if ((poll_descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        errno = ECONNRESET;
        return -1;
    }
    errno = EIO;
    return -1;
}

static int retain_socket_for_attribution(void) {
    struct timespec delay = {
        .tv_sec = 1,
        .tv_nsec = 0,
    };

    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static int connect_with_timeout(int descriptor,
                                const struct sockaddr_in *address,
                                int timeout_ms) {
    int socket_error = 0;
    socklen_t socket_error_length = sizeof(socket_error);

    if (connect(descriptor, (const struct sockaddr *)address,
                sizeof(*address)) == 0) {
        return 0;
    }
    if (errno != EINPROGRESS ||
        wait_for_socket(descriptor, POLLOUT, timeout_ms) != 0 ||
        getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_length) != 0) {
        return -1;
    }
    if (socket_error != 0) {
        errno = socket_error;
        return -1;
    }
    return 0;
}

static int send_all(int descriptor, const void *buffer, size_t length,
                    int timeout_ms) {
    const unsigned char *position = buffer;
    size_t remaining = length;

    while (remaining != 0) {
        ssize_t written;
        if (wait_for_socket(descriptor, POLLOUT, timeout_ms) != 0) {
            return -1;
        }
        written = send(descriptor, position, remaining, MSG_NOSIGNAL);
        if (written < 0 && (errno == EINTR || errno == EAGAIN ||
                            errno == EWOULDBLOCK)) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        position += (size_t)written;
        remaining -= (size_t)written;
    }
    return 0;
}

static int run_tcp(const char *address_text, unsigned long port,
                   int timeout_ms) {
    struct sockaddr_in address;
    char request[256];
    unsigned char response[32];
    int descriptor = -1;
    int request_length;
    ssize_t received;
    int status = 1;

    if (make_address(address_text, port, &address) != 0) {
        fprintf(stderr, "invalid IPv4 address\n");
        return 2;
    }
    request_length = snprintf(request, sizeof(request),
                              "GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
                              address_text);
    if (request_length < 0 || (size_t)request_length >= sizeof(request)) {
        fprintf(stderr, "HTTP request is too large\n");
        return 2;
    }
    descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0 || set_nonblocking(descriptor) != 0 ||
        connect_with_timeout(descriptor, &address, timeout_ms) != 0 ||
        send_all(descriptor, request, (size_t)request_length, timeout_ms) != 0 ||
        wait_for_socket(descriptor, POLLIN, timeout_ms) != 0) {
        perror("tcp client");
        goto finished;
    }
    do {
        received = recv(descriptor, response, sizeof(response), 0);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
        if (received < 0) {
            perror("tcp receive");
        }
        goto finished;
    }
    if (retain_socket_for_attribution() != 0) {
        perror("tcp attribution hold");
        goto finished;
    }
    status = 0;

finished:
    if (descriptor >= 0) {
        close(descriptor);
    }
    return status;
}

static int run_udp(const char *address_text, unsigned long port,
                   unsigned long source_port, int timeout_ms,
                   const char *payload) {
    struct sockaddr_in address;
    struct sockaddr_in source_address;
    unsigned char response[4096];
    size_t payload_length = strlen(payload);
    int descriptor = -1;
    int reuse_address = 1;
    ssize_t received;
    int status = 1;

    if (payload_length == 0 || payload_length > sizeof(response) ||
        make_address(address_text, port, &address) != 0) {
        fprintf(stderr, "invalid UDP arguments\n");
        return 2;
    }
    memset(&source_address, 0, sizeof(source_address));
    source_address.sin_family = AF_INET;
    source_address.sin_addr.s_addr = htonl(INADDR_ANY);
    source_address.sin_port = htons((uint16_t)source_port);

    descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (descriptor < 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse_address,
                   sizeof(reuse_address)) != 0 ||
        bind(descriptor, (const struct sockaddr *)&source_address,
             sizeof(source_address)) != 0 ||
        set_nonblocking(descriptor) != 0 ||
        connect(descriptor, (const struct sockaddr *)&address,
                sizeof(address)) != 0 ||
        send_all(descriptor, payload, payload_length, timeout_ms) != 0 ||
        wait_for_socket(descriptor, POLLIN, timeout_ms) != 0) {
        perror("udp client");
        goto finished;
    }
    do {
        received = recv(descriptor, response, sizeof(response), 0);
    } while (received < 0 && errno == EINTR);
    if (received < 0 || (size_t)received != payload_length ||
        memcmp(response, payload, payload_length) != 0) {
        if (received < 0) {
            perror("udp receive");
        } else {
            fprintf(stderr, "unexpected UDP response\n");
        }
        goto finished;
    }
    if (retain_socket_for_attribution() != 0) {
        perror("udp attribution hold");
        goto finished;
    }
    if (fwrite(response, 1, (size_t)received, stdout) != (size_t)received ||
        fflush(stdout) != 0) {
        perror("udp output");
        goto finished;
    }
    status = 0;

finished:
    if (descriptor >= 0) {
        close(descriptor);
    }
    return status;
}

int main(int argc, char **argv) {
    unsigned long port;
    unsigned long source_port;
    unsigned long timeout_ms;

    if (argc == 5 && strcmp(argv[1], "tcp") == 0) {
        if (parse_number(argv[3], UINT16_MAX, &port) != 0 ||
            parse_number(argv[4], 60000, &timeout_ms) != 0) {
            usage(argv[0]);
            return 2;
        }
        return run_tcp(argv[2], port, (int)timeout_ms);
    }
    if (argc == 7 && strcmp(argv[1], "udp") == 0) {
        if (parse_number(argv[3], UINT16_MAX, &port) != 0 ||
            parse_number(argv[4], UINT16_MAX, &source_port) != 0 ||
            parse_number(argv[5], 60000, &timeout_ms) != 0) {
            usage(argv[0]);
            return 2;
        }
        return run_udp(argv[2], port, source_port, (int)timeout_ms, argv[6]);
    }
    usage(argv[0]);
    return 2;
}
