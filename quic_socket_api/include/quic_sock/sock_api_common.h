/** \file */
//
// Created by thomas on 26/09/22.
//

#ifndef QUIC_SOCK_SOCK_API_COMMON_H
#define QUIC_SOCK_SOCK_API_COMMON_H

/**
 * Application-Layer Protocol Negotiation (ALPN) structure.
 */
struct alpn_buffer {
    size_t alpn_size; /** String length of alpn_name */
    const unsigned char *alpn_name; /** name of the ALPN  */
};

/**
 * Represents the TLS configuration to use.
 * Used for both passive (listen) or active (connect)
 * socket.
 */
struct tls_config {
    int insecure; /**< should the remote certificate be verified ? 1 if yes. 0 if no */
    const char *root_ca_file; /**< Root CA to use to verify incoming certificates. Null for default certificate if default_root_ca is set */
    const char *secret_log_file; /**< If not null, tells the implementation to store the TLS secrets in the file pointed to by this field.  */
    const char *certificate_file; /**< path to the x.509 certificate */
    const char *private_key_file; /**< path to the private key */
    int nb_alpn; /**< number of ALPN contained in the alpn_buffer array */
    const char *sni; /**< sni of the remote target to contact */
    int require_client_authentication; /**< set to 1 if the client must be authenticated. 0 otherwise */
    /* /!\ alpn MUST be the last field of this structure */
    struct alpn_buffer alpn[0]; /**< A space for the alpn array must be reserved */
};

#endif //QUIC_SOCK_SOCK_API_COMMON_H
