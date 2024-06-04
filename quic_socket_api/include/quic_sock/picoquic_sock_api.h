/** \file */
//
// Created by thomas on 26/09/22.
//

#ifndef QUIC_SOCK_PICOQUIC_SOCK_API_H
#define QUIC_SOCK_PICOQUIC_SOCK_API_H


#include <unistd.h>
#include "sock_api_common.h"
#include <sys/socket.h>

int picoquic_init(const char *app_name);

void picoquic_set_default_root_ca_path(const char *root_cert_path);

void picoquic_finished(void);

int picoquic_socket(void);

int picoquic_bind(int sockfd,
                const struct sockaddr *addr,
                socklen_t addrlen);

int picoquic_listen(int sockfd,
                  struct tls_config *tls_config);

int picoquic_accept(int socket,
                  struct sockaddr *restrict address,
                  socklen_t *restrict address_len);

int picoquic_accept_stream(int socket,
                           struct sockaddr *restrict address,
                           socklen_t *restrict address_len);

int picoquic_open_stream(int socket);

int picoquic_connect(int sockfd,
                   const struct sockaddr *addr,
                   socklen_t addrlen,
                   struct tls_config *tls_config);

ssize_t picoquic_read(int fd,
                    void *buf,
                    size_t count);

ssize_t picoquic_write(int fd,
                     const void *buf,
                     size_t count);

int picoquic_s_close(int fd);

int picoquic_getsockname(int fd, struct sockaddr *addr, socklen_t *restrict len, unsigned long *ifindex);

#endif //QUIC_SOCK_PICOQUIC_SOCK_API_H
