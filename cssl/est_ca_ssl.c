/* Copyright (c) 2018 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "_cgo_export.h"

unsigned int cssl_c_psk_client_cb(SSL *ssl, const char *hint, char *id,
                                  unsigned int max_id_len, unsigned char *psk,
                                  unsigned int max_psk_len)
{
	return (cssl_go_psk_client_cb(ssl, hint, id, max_id_len, psk, max_psk_len));
}
unsigned int cssl_c_psk_server_cb(SSL * ssl, const char *identity,
                                  unsigned char *psk, unsigned int max_psk_len)
{
	return (cssl_go_psk_server_cb(ssl, identity, psk, max_psk_len));
}

void cssl_c_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len,
                         SSL *ssl, void *arg)
{
	const char *str_write_p, *str_version, *str_content_type = "",
               *str_details1 = "", *str_details2= "";

    str_write_p = write_p ? ">>>" : "<<<";

	if (!cssl_go_getdebugflag()) {
		return;
	}

    switch (version) {
        case SSL2_VERSION:
            str_version = "SSL 2.0";
            break;
        case SSL3_VERSION:
            str_version = "SSL 3.0 ";
            break;
        case TLS1_VERSION:
            str_version = "TLS 1.0 ";
            break;
        case TLS1_1_VERSION:
            str_version = "TLS 1.1 ";
            break;
        case TLS1_2_VERSION:
            str_version = "TLS 1.2 ";
            break;
        case DTLS1_VERSION:
            str_version = "DTLS 1.0";
            break;
        case DTLS1_BAD_VER:
            str_version = "DTLS 1.0 (any-connect)";
            break;
		default:
            if (len == 5 || len == 13) {
                str_version = "TLS Header";
            } else {
                str_version = "???";
            }
    }

    if (version == SSL3_VERSION ||
            version == TLS1_VERSION ||
            version == TLS1_1_VERSION ||
            version == TLS1_2_VERSION ||
            version == DTLS1_VERSION) {
        switch (content_type) {
            case 20:
                str_content_type = "ChangeCipherSpec";
                break;
            case 21:
                str_content_type = "Alert";
                break;
            case 22:
                str_content_type = "Handshake";
                break;
        }
		if (content_type == 21) {
            str_details1 = ", ???";

            if (len == 2) {
                switch (((const unsigned char*)buf)[0]) {
                    case 1:
                        str_details1 = ", warning";
                        break;
                    case 2:
                        str_details1 = ", fatal";
                        break;
                }

                str_details2 = " ???";
				switch (((const unsigned char*)buf)[1]) {
                    case 0:
                        str_details2 = " close_notify";
                        break;
                    case 10:
                        str_details2 = " unexpected_message";
                        break;
                    case 20:
                        str_details2 = " bad_record_mac";
                        break;
                    case 21:
                        str_details2 = " decryption_failed";
                        break;
                    case 22:
                        str_details2 = " record_overflow";
                        break;
                    case 30:
                        str_details2 = " decompression_failure";
                        break;
                    case 40:
                        str_details2 = " handshake_failure";
                        break;
                    case 42:
                        str_details2 = " bad_certificate";
                        break;
                    case 43:
                        str_details2 = " unsupported_certificate";
                        break;
					case 44:
                        str_details2 = " certificate_revoked";
                        break;
                    case 45:
                        str_details2 = " certificate_expired";
                        break;
                    case 46:
                        str_details2 = " certificate_unknown";
                        break;
                    case 47:
                        str_details2 = " illegal_parameter";
                        break;
                    case 48:
                        str_details2 = " unknown_ca";
                        break;
                    case 49:
                        str_details2 = " access_denied";
                        break;
                    case 50:
                        str_details2 = " decode_error";
                        break;
                    case 51:
                        str_details2 = " decrypt_error";
                        break;
                    case 60:
                        str_details2 = " export_restriction";
                        break;
					case 70:
                        str_details2 = " protocol_version";
                        break;
                    case 71:
                        str_details2 = " insufficient_security";
                        break;
                    case 80:
                        str_details2 = " internal_error";
                        break;
                    case 90:
                        str_details2 = " user_canceled";
                        break;
                    case 100:
                        str_details2 = " no_renegotiation";
                        break;
                    case 110:
                        str_details2 = " unsupported_extension";
                        break;
                    case 111:
                        str_details2 = " certificate_unobtainable";
                        break;
                    case 112:
                        str_details2 = " unrecognized_name";
                        break;
                    case 113:
                        str_details2 = " bad_certificate_status_response";
                        break;
                    case 114:
                        str_details2 = " bad_certificate_hash_value";
                        break;
					case 115:
                        str_details2 = " unknown_psk_identity";
                        break;
                }
            }
        }
		if (content_type == 22) {
            str_details1 = "???";

            if (len > 0) {
                switch (((const unsigned char*)buf)[0]) {
                    case 0:
                        str_details1 = ", HelloRequest";
                        break;
                    case 1:
                        str_details1 = ", ClientHello";
                        break;
                    case 2:
                        str_details1 = ", ServerHello";
                        break;
                    case 3:
                        str_details1 = ", HelloVerifyRequest";
                        break;
                    case 11:
                        str_details1 = ", Certificate";
                        break;
                    case 12:
                        str_details1 = ", ServerKeyExchange";
                        break;
                    case 13:
                        str_details1 = ", CertificateRequest";
                        break;
                    case 14:
                        str_details1 = ", ServerHelloDone";
                        break;
					case 15:
                        str_details1 = ", CertificateVerify";
                        break;
                    case 16:
                        str_details1 = ", ClientKeyExchange";
                        break;
                    case 20:
                        str_details1 = ", Finished";
                        break;
                }
            }
        }
        if (content_type == 24) {
            str_details1 = ", Heartbeat";

            if (len > 0) {
                switch (((const unsigned char*)buf)[0]) {
                    case 1:
                        str_details1 = ", HeartbeatRequest";
                        break;
                    case 2:
                        str_details1 = ", HeartbeatResponse";
                        break;
                }
            }
        }
    }
	printf("\n%s %s%s [length %04lx]%s%s", str_write_p, str_version,
              str_content_type, (unsigned long)len, str_details1, str_details2);

}

void cssl_c_info_callback(const SSL *s, int where, int ret)
{
	int w;
	const char *str;

	if (!cssl_go_getdebugflag()) {
		return;
	}
    /* Stop client initiated re-negotiation */
    if ((s->server) && (where & SSL_CB_HANDSHAKE_DONE)) {
        if (s->s3) {
            s->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
    }

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) {
        str = "SSL_connect";
    } else if (w & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    } else {
        str = "undefined";
    }

    if (where & SSL_CB_LOOP) {
        printf("\n%s:%s",str,SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        printf("\nSSL3 alert %s:%s:%s",
                  str,
				  SSL_alert_type_string_long(ret),
                  SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            printf("\n%s:failed in %s",
                      str,SSL_state_string_long(s));
        } else if (ret < 0) {
            /* SSL_get_error cannot modify s */
            int i = SSL_get_error((SSL *)s, ret);
            switch (i) {
                case SSL_ERROR_WANT_READ:
                    printf("\n%s:would block on read in %s",
                              str,SSL_state_string_long(s));
                    break;
                case SSL_ERROR_WANT_WRITE:
                    printf("\n%s:would block on write in %s",
                              str,SSL_state_string_long(s));
                    break;
            }
        }
    } else if (where & SSL_CB_HANDSHAKE_START) {
        printf("\nHandshake start: %s",
                  SSL_state_string_long(s));
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
        printf("\nHandshake done: %s",
                  SSL_state_string_long(s));
    }
}

int CSSL_CTX_set_tmp_ecdh(SSL_CTX *sslctx, EC_KEY *key)
{
	return SSL_CTX_set_tmp_ecdh(sslctx, key);
}

int CSSL_CTX_set_options(SSL_CTX *sslctx)
{
	return SSL_CTX_set_options(sslctx, SSL_OP_ALL);
}

void COpenSSL_add_all_algorithms(void)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_ssl_algorithms();
}

int CSSL_CTX_set_ecdh_auto(SSL_CTX *sslctx, int onoff)
{
	return SSL_CTX_set_ecdh_auto(sslctx, onoff);
}
