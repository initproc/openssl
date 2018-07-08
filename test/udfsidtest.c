/* Written by Jiwook Kim for the purpose of tls client test */
/* ====================================================================
 * Copyright (c) 1998-2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#define MAX_HOST_LEN 128
#define MAX_UDF_SID_LEN 32
#define MAX_UDF_STK_LEN 128
#define MAX_TLS_METHOD_LEN 3

#define DEFAULT_MAX_REQ_CNT 1

#define ENABLED 1
#define DISABLED -1
#define DEFAULT_UDF_SID_MODE DISABLED
#define DEFAULT_UDF_STK_MODE DISABLED
#define DEFAULT_PORT 443

#define CIPHER_LIST "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS"

#define MAX_HTTP_MSG_LEN 1024
#define MAX_RECV_BUF_LEN 1024

typedef struct request_info_s {
    char host[MAX_HOST_LEN];
    int port;

    int use_udf_sid;
    char udf_sid[MAX_UDF_SID_LEN + 1];

    int use_udf_stk;
    char udf_stk[MAX_UDF_STK_LEN + 1];

    int max_req_cnt;
    int keepalive_flag;
    int session_resume;

    char tls_method[MAX_TLS_METHOD_LEN];
} request_conf_t;

void usage(int argc, char *argv[0]) {
    printf("\t%s -h example.com -r 3 -u \"user_defined_session_id\" -k\n", argv[0]);
    printf("Option : \n");
    printf("\t-h: domain\n");
    printf("\t-p: port\n");
    printf("\t-r: a number of requests\n");
    printf("\t-u: user defined session id\n");
    printf("\t-k: flag for keepalive\n");
    printf("\t-s: flag for tls session resumeption\n");
    printf("\t-t: tls ext session ticket\n");
    printf("\t-v: tls version(ex: 1.0 1.1 1.2)\n");
}

void init_openssl(void) {
    (void)SSL_library_init();
    SSL_load_error_strings();

    OPENSSL_config(NULL);
}

void print_ssl_err(const char *func_nm) {
    unsigned long err = 0;
    const char *str = NULL;

    err = ERR_get_error();
    str = ERR_reason_error_string(err);

    if(str) {
        fprintf(stderr, "%s\n", str);
    } else {
        fprintf(stderr, "%s failed: (0x%lu)\n", func_nm, err);
    }
}

const SSL_METHOD *get_TLS_method(request_conf_t *req_conf) {
    if (strcmp(req_conf->tls_method, "1.0")) {
        printf("TLSv1 choosed\n");
        return TLSv1_method();
    }
    if (strcmp(req_conf->tls_method, "1.1")) {
        printf("TLSv1.1 choosed\n");
        return TLSv1_1_method();
    }
    if (strcmp(req_conf->tls_method, "1.2")) {
        printf("TLSv1.2 choosed\n");
        return TLSv1_2_method();
    }

    // TLSv1.1 is default;
    printf("TLSv1.1 choosed(default)\n");
    return TLSv1_1_method();
}

int is_enabled_stk(request_conf_t *req_conf) {
    if (req_conf->use_udf_stk == ENABLED) {
        return 1;
    }

    return 0;
}

int is_enabled_udf_sid(request_conf_t *req_conf) {
    if (req_conf->use_udf_sid == ENABLED) {
        return 1;
    }

    return 0;
}

int is_enabled_keepalive(request_conf_t *req_conf) {
    if (req_conf->keepalive_flag == ENABLED) {
        return 1;
    }

    return 0;
}

int is_enabled_session_resumption(request_conf_t *req_conf) {
    if (req_conf->session_resume == ENABLED) {
        return 1;
    }

    return 0;
}

int tls_request(request_conf_t *req_conf) {
    int req_cnt = 0, max_req_cnt = 0;
    long res = 1;

    BIO *cbio = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    long unsigned flags = 0;
    SSL_SESSION *session = NULL;
    const SSL_METHOD *method = NULL;

    char port[6] = { 0x00, };
    char hostname[MAX_HOST_LEN] = { 0x00, };
    char http_buf[MAX_HTTP_MSG_LEN] = { 0x00, };

    int recv_len = 0;
    char recv_buf[MAX_RECV_BUF_LEN] = { 0x00, };

    init_openssl();

    max_req_cnt = req_conf->max_req_cnt;
    method = get_TLS_method(req_conf);
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        print_ssl_err("SSL_CTX_new");
        return -1;
    }

    if (is_enabled_stk(req_conf)) {
        flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;

    } else {
        flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET;
    }

    SSL_CTX_set_options(ctx, flags);

    // snprintf(hostname, MAX_HOST_LEN * 2, "%s:%s:%d", req_conf->host, ":", req_conf->port);
    strcat(hostname, req_conf->host);
    strcat(hostname, ":");
    snprintf(port, sizeof(port), "%d", req_conf->port);
    strcat(hostname, port);

    snprintf(http_buf, MAX_HTTP_MSG_LEN,
            "GET / HTTP/1.1\r\nHOST: %s\r\n\r\n", req_conf->host);

    printf("\n");

    for (req_cnt = 0; req_cnt < max_req_cnt; req_cnt++) {
        printf("Request start\n");

        if (is_enabled_keepalive(req_conf) == 0
                || (is_enabled_keepalive(req_conf) && req_cnt == 0)) {

            // if keepalive enabled,
            // ssl context initialization is runned
            // only for the first time
            cbio = BIO_new_ssl_connect(ctx);

            if (cbio == NULL) {
                print_ssl_err("BIO_new_ssl_connect");
                return -1;
            }

            printf("connect to: [%s]\n", hostname);
            res = BIO_set_conn_hostname(cbio, hostname);

            if (res != 1) {
                print_ssl_err("BIO_set_conn_hostname");
                return -1;
            }

            res = BIO_get_ssl(cbio, &ssl);

            if (res != 1) {
                print_ssl_err("BIO_set_conn_hostname");
                return -1;
            }

            if (is_enabled_udf_sid(req_conf)) {
                /* if session resumption is enabled,
                   skip the user defined session except for
                   the first time */
                if (is_enabled_session_resumption(req_conf)
                        && req_cnt > 0) {
                    printf("clear udf sid\n");
                    SSL_clear_udf_sid(ssl);
                } else {
                    size_t sid_len = strlen(req_conf->udf_sid);

                    if (sid_len > 0) {
                        SSL_set_udf_sid(ssl,
                                (unsigned char *)req_conf->udf_sid,
                                sid_len);
                    }
                }
            }

            if (is_enabled_stk(req_conf)) {
                if (is_enabled_session_resumption(req_conf)
                        && req_cnt > 0) {
                    /* DNT */
                } else {
                    size_t stk_len = strlen(req_conf->udf_stk);

                    if (stk_len > 0) {
                        SSL_set_session_ticket_ext(ssl,
                                (void *) req_conf->udf_stk,
                                (int) stk_len);
                    }
                }
            }

            res = SSL_set_cipher_list(ssl, CIPHER_LIST);

            if (res != 1) {
                print_ssl_err("SSL_set_cipher_list");
                return -1;
            }

            res = SSL_set_tlsext_host_name(ssl, hostname);

            if (res != 1) {
                print_ssl_err("SSL_set_tlsext_host_name");
                return -1;
            }

            if (is_enabled_session_resumption(req_conf)
                    && session != NULL) {
                printf("set reused session: %p\n", session);
                SSL_set_session(ssl, session);
            }

            res = SSL_connect(ssl);

            if (res != 1) {
                print_ssl_err("BIO_do_connect");
                return -1;
            }
        }

        printf("using fd: %d\n", SSL_get_fd(ssl));

        if (SSL_session_reused(ssl)) {
            printf("Session reused\n");
        } else {
            printf("New Session\n");
        }

        // send
        BIO_puts(cbio, http_buf);

        recv_len = BIO_read(cbio, recv_buf, sizeof(recv_buf));

        if (recv_len > 0) {
            printf("recv len: %d\n", recv_len);
            //printf("received: %s\n", recv_buf);
        }

        if (is_enabled_session_resumption(req_conf)) {
            if (session != NULL) {
                printf("dec ref of ssl session\n");
                SSL_SESSION_free(session);
            }

            printf("inc ref of ssl session\n");
            session = SSL_get1_session(ssl);
        }

        if (is_enabled_keepalive(req_conf)) {
            printf("keepalived enabled\n");
        } else {
            printf("close connection\n");

            SSL_shutdown(ssl);
            close(SSL_get_fd(ssl));
            SSL_free(ssl);

            ssl = NULL;
        }

        printf("\n");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int opt;

    request_conf_t req_conf;

    if (argc == 1) {
        usage(argc, argv);
        return 0;
    }

    memset(&req_conf, 0x00, sizeof(request_conf_t));

    req_conf.max_req_cnt = DEFAULT_MAX_REQ_CNT;
    req_conf.use_udf_sid = DEFAULT_UDF_SID_MODE;
    req_conf.use_udf_sid = DEFAULT_UDF_STK_MODE;
    req_conf.port = DEFAULT_PORT;

    while (1) {
        opt = getopt(argc, argv, "h:p:u:r:t:v:ks");

        if (opt == -1) {
            break;
        }

        switch (opt) {
            case 'h': // host
                printf("-%c with value [%s]\n", opt, optarg);
                memcpy(req_conf.host, optarg, strnlen(optarg, MAX_HOST_LEN));
                break;
            case 'p': // port
                printf("-%c with value [%s](port)\n", opt, optarg);
                req_conf.port = atoi(optarg);
                break;
            case 'u': // udf sid
                printf("-%c with value [%s](udf_sid)\n", opt, optarg);
                req_conf.use_udf_sid = ENABLED;

                if (optarg != NULL || optarg[0] != '\0') {
                    memcpy(req_conf.udf_sid, optarg, strnlen(optarg, MAX_UDF_SID_LEN));
                }
                break;
            case 'r': // number of reqs
                printf("-%c with value [%s](max reqs)\n", opt, optarg);
                req_conf.max_req_cnt = atoi(optarg);
                break;
            case 't': // session ticket
                printf("-%c with value [%s](session ticket)\n", opt, optarg);
                req_conf.use_udf_stk = ENABLED;

                if (optarg != NULL || optarg[0] != '\0') {
                    memcpy(req_conf.udf_stk, optarg, strnlen(optarg, MAX_UDF_STK_LEN));
                }
                break;
            case 'v': // tls version
                printf("-%c with value [%s](tls method)\n",
                        opt, optarg);
                memcpy(req_conf.tls_method, optarg, strnlen(optarg, MAX_TLS_METHOD_LEN));
                break;
            case 'k': // flag for keepalive
                printf("-%c is set(keepalive)\n", opt);
                req_conf.keepalive_flag = ENABLED;
                break;
            case 's': // flag for session resumption
                printf("-%c is set(session resumption)\n", opt);
                req_conf.session_resume = ENABLED;
                break;
            case '?':
                usage(argc, argv);
                return 0;
            default:
                usage(argc, argv);
                return 0;
        }
    }

    if (strnlen(req_conf.host, MAX_HOST_LEN) == 0) {
        usage(argc, argv);
        return 0;
    }

    tls_request(&req_conf);

    return 0;
}
