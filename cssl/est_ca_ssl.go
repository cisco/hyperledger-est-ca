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

package cssl

/*
 #cgo LDFLAGS: -lssl -lcrypto -ldl
 #include <stdint.h>
 #include <stdio.h>
 #include <string.h>
 #include <openssl/evp.h>
 #include <openssl/rand.h>
 #include <openssl/ssl.h>
 #include <openssl/dh.h>
 #include <openssl/err.h>
 #include <openssl/crypto.h>

 extern unsigned int cssl_c_psk_client_cb(SSL *ssl, const char *hint, char *id,
 										  unsigned int max_id_len, unsigned char *psk,
										  unsigned int max_psk_len);

 extern unsigned int cssl_c_psk_server_cb(SSL * ssl, const char *identity,
 										  unsigned char *psk, unsigned int max_psk_len);

 extern void cssl_c_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len,
 								 SSL *ssl, void *arg);

 extern void cssl_c_info_callback(const SSL *s, int where, int ret);
 extern int CSSL_CTX_set_tmp_ecdh(SSL_CTX *, EC_KEY *);
 extern int CSSL_CTX_set_ecdh_auto(SSL_CTX *, int);
 extern int CSSL_CTX_set_options(SSL_CTX *);
 extern void COpenSSL_add_all_algorithms(void);

*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

const (
	SSL_MODE_SERVER = 0
	SSL_MODE_CLIENT = 1
)

const (
	SSL_OP_ALL uint32 = 0x000FFFFF
)

const (
	SSL_VERIFY_NONE                 uint8 = 0x00
	SSL_VERIFY_PEER                 uint8 = 0x01
	SSL_VERIFY_FAIL_IF_NO_PEER_CERT uint8 = 0x02
	SSL_VERIFY_CLIENT_ONCE          uint8 = 0x04
)

const (
	SSL_FILETYPE_PEM     = 1
	SSL_FILETYPE_ASN1    = 2
	SSL_FILETYPE_DEFAULT = 3
)

const (
	NID_X9_62_prime256v1 = 415
	secp256k1            = 714
)

const (
	SSL_ERROR_NONE             = 0
	SSL_ERROR_SSL              = 1
	SSL_ERROR_WANT_READ        = 2
	SSL_ERROR_WANT_WRITE       = 3
	SSL_ERROR_WANT_X509_LOOKUP = 4
	SSL_ERROR_SYSCALL          = 5
	SSL_ERROR_ZERO_RETURN      = 6
	SSL_ERROR_WANT_CONNECT     = 7
)

const (
	CSSL_APP_ERR_UNKNOWN      = 0
	CSSL_APP_ERR_EOK          = 1
	CSSL_APP_ERR_WANT_READ    = 2
	CSSL_APP_ERR_WANT_WRITE   = 3
	CSSL_APP_ERR_SYSCALL      = 4
	CSSL_APP_ERR_PEERCLOSE    = 5
	CSSL_APP_ERR_RESOURCES    = 6
	CSSL_APP_ERR_INVALID_ARGS = 7
)

var ssl_init bool
var cssl_debug bool
var cssl_psk_cb CSSLPSKCb
var cssl_psk_admin_cb CSSLPSKCb
var admn_identifier = "CBAABC"
var cssl_fdmap map[int32]*CSSL

type CSSLPSKCb func(id string) string

type CSSL struct {
	fd      int
	mode    uint8
	ssl_up  bool
	isadmin bool
	pskid   *string
	ssl     *C.struct_ssl_st
	ssl_ctx *C.struct_ssl_ctx_st
}

/* Function to set debug level */
func CSSLSetDebug(flag bool) {
	cssl_debug = flag
}

/* Function to initialize the SSL Library */
func CSSLInit() {
	if ssl_init != true {
		C.SSL_library_init()
		C.SSL_load_error_strings()
		C.COpenSSL_add_all_algorithms()
		cssl_fdmap = make(map[int32]*CSSL)
		ssl_init = true
	}
}

func CSSLAddFdToMap(fd int, cssl *CSSL) {
	cssl_fdmap[int32(fd)] = cssl
}

func CSSLDeleteFdMap(fd int) {
	delete(cssl_fdmap, int32(fd))
}

func CSSLGetByFd(fd int) *CSSL {
	return cssl_fdmap[int32(fd)]
}

func CSSLSetAdminMode(cssl *CSSL) {
	cssl.isadmin = true
}

/* Function to create a new Server SSL binding */
func CSSLGetNewServer(fd int) *CSSL {
	var cssl *CSSL

	cssl = new(CSSL)
	if cssl == nil {
		fmt.Printf("\nCould not allocate new CSSL")
		return nil
	}

	cssl.mode = SSL_MODE_SERVER
	cssl.ssl_ctx = C.SSL_CTX_new(C.TLSv1_2_server_method())
	cssl.fd = fd
	CSSLAddFdToMap(fd, cssl)

	C.SSL_CTX_set_msg_callback(cssl.ssl_ctx, (*[0]byte)(C.cssl_c_msg_callback))
	C.SSL_CTX_set_info_callback(cssl.ssl_ctx, (*[0]byte)(C.cssl_c_info_callback))
	C.SSL_CTX_set_quiet_shutdown(cssl.ssl_ctx, 1)
	retec := C.CSSL_CTX_set_ecdh_auto(cssl.ssl_ctx, 1)
	if int(retec) != 1 {
		fmt.Printf("\nFailed to enable ecdh auto mode")
	}
	C.CSSL_CTX_set_options(cssl.ssl_ctx)

	return cssl
}

/* Function to get a new SSL servelet */
func CSSLGetNewServelet(fd int, cssl *CSSL) (*CSSL, uint8) {
	var cssl_new *CSSL
	var retval uint8

	if (fd <= 0) || (cssl == nil) || (cssl.ssl_ctx == nil) {
		return nil, CSSL_APP_ERR_INVALID_ARGS
	}
	cssl_new = new(CSSL)
	if cssl_new == nil {
		fmt.Printf("\nCould not allocate new CSSL")
		return nil, CSSL_APP_ERR_RESOURCES
	}

	cssl_new.mode = SSL_MODE_SERVER
	cssl_new.ssl = C.SSL_new(cssl.ssl_ctx)
	if cssl_new.ssl == nil {
		fmt.Printf("\nCould not allocate SSL for servelet")
		return nil, CSSL_APP_ERR_RESOURCES
	}
	/* set admin mode to recognize if Admin mode */
	if cssl.isadmin {
		cssl_new.isadmin = true
		CSSLSetAdmin(cssl_new)
	}

	cssl_new.fd = fd
	ret := C.SSL_set_fd(cssl_new.ssl, (C.int)(fd))
	if ret != 1 {
		fmt.Printf("\nCould not set SSL fd %d", ret)
		return nil, CSSL_APP_ERR_UNKNOWN
	}
	CSSLAddFdToMap(fd, cssl_new)

	ret = C.SSL_accept(cssl_new.ssl)
	if ret > 0 {
		fmt.Printf("\nSSL handshake completed successfully")
		cssl_new.ssl_up = true
		retval = CSSL_APP_ERR_EOK
	} else {
		app_ret := C.SSL_get_error(cssl_new.ssl, ret)
		fmt.Printf("\nSSL Accept returned error %d", uint8(app_ret))
		retval = CSSLTranslateSSLError(uint8(app_ret))
	}

	return cssl_new, retval
}

/* Function to Get new Client SSL binding */
func CSSLGetNewClient(fd int) *CSSL {
	var cssl *CSSL

	if fd <= 0 {
		return nil
	}

	cssl = new(CSSL)
	if cssl == nil {
		return nil
	}

	cssl.mode = SSL_MODE_CLIENT
	cssl.ssl_ctx = C.SSL_CTX_new(C.TLSv1_2_client_method())
	cssl.fd = fd
	CSSLAddFdToMap(fd, cssl)

	C.SSL_CTX_set_msg_callback(cssl.ssl_ctx, (*[0]byte)(C.cssl_c_msg_callback))
	C.SSL_CTX_set_info_callback(cssl.ssl_ctx, (*[0]byte)(C.cssl_c_info_callback))
	//C.SSL_CTX_set_options(cssl.ssl_ctx, (C.uint32_t)(SSL_OP_ALL));
	retec := C.CSSL_CTX_set_ecdh_auto(cssl.ssl_ctx, 1)
	if int(retec) != 1 {
		fmt.Printf("\nFailed to enable ecdh auto mode")
	}

	return cssl
}

/* Function to set the Cipher from cipher string */
func CSSLSetCipher(cssl *CSSL, cipher string) bool {
	if cssl == nil {
		return false
	}

	cip := C.CString(cipher)
	ret := C.SSL_CTX_set_cipher_list(cssl.ssl_ctx, cip)
	C.free(unsafe.Pointer(cip))
	if ret == 0 {
		fmt.Printf("\nCould not set the cipher list %s", cipher)
		return false
	}

	/* Set PSK Call back if the cipher contains psk */
	if strings.Contains(cipher, "PSK") {
		if cssl.mode == SSL_MODE_SERVER {
			C.SSL_CTX_set_psk_server_callback(cssl.ssl_ctx, (*[0]byte)(C.cssl_c_psk_server_cb))
		} else {
			C.SSL_CTX_set_psk_client_callback(cssl.ssl_ctx, (*[0]byte)(C.cssl_c_psk_client_cb))
		}
	}
	/* Set Certificate Verify callback */
	if strings.Contains(cipher, "RSA") {
		//C.SSL_CTX_set_cert_verify_callback(cssl.ssl_ctx, (*[0]byte)(C.cssl_c_cert_verify_cb));
	}

	if strings.Contains(cipher, "ECDHE") {
		fmt.Printf("\nECDHE Cipher configured")
	}

	/* TODO:Add DHE cases later */

	return true
}

/* Function to set PSK hint */
func CSSLSetPSKHint(cssl *CSSL, hint string) bool {
	if cssl == nil {
		return false
	}
	chint := C.CString(hint)
	ret := C.SSL_CTX_use_psk_identity_hint(cssl.ssl_ctx, chint)
	C.free(unsafe.Pointer(chint))

	if int(ret) != 1 {
		return false
	}

	return true
}

/* Enable peer cert validation */
func CSSLEnablePeerCertValidation(cssl *CSSL) bool {
	if cssl == nil || cssl.ssl_ctx == nil {
		return false
	}

	C.SSL_CTX_set_verify(cssl.ssl_ctx,
		(C.int)(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE),
		nil)
	C.SSL_CTX_set_verify_depth(cssl.ssl_ctx, 0)

	return true
}

/* Set PSK Callback for fetching key from id */
func CSSLSetPSKCb(cb CSSLPSKCb) {
	cssl_psk_cb = cb
}

/* Set PSK Callback for fetching key from id */
func CSSLSetAdminPSKCb(cb CSSLPSKCb) {
	cssl_psk_admin_cb = cb
}

/* Translate SSL Error to APP Error */
func CSSLTranslateSSLError(err uint8) uint8 {
	var x uint8

	switch err {
	case SSL_ERROR_WANT_READ:
		x = CSSL_APP_ERR_WANT_READ
	case SSL_ERROR_WANT_WRITE:
		x = CSSL_APP_ERR_WANT_WRITE
	case SSL_ERROR_SYSCALL:
		x = CSSL_APP_ERR_SYSCALL
	default:
		x = CSSL_APP_ERR_UNKNOWN
	}
	return x
}

/* Connect to the SSL server */
func CSSLClientConnect(cssl *CSSL) uint8 {
	var retval uint8

	if cssl == nil {
		return CSSL_APP_ERR_UNKNOWN
	}

	if cssl == nil || cssl.mode != SSL_MODE_CLIENT {
		return CSSL_APP_ERR_UNKNOWN
	}

	cssl.ssl = C.SSL_new(cssl.ssl_ctx)
	if cssl.ssl == nil {
		fmt.Printf("\nCould not allocate SSL for client")
		return CSSL_APP_ERR_RESOURCES
	}

	ret := C.SSL_set_fd(cssl.ssl, (C.int)(cssl.fd))
	if ret != 1 {
		fmt.Printf("\nCould not set SSL fd %d", ret)
		return CSSL_APP_ERR_SYSCALL
	}

	/* Also set the psk id into SSL */
	if cssl.pskid != nil {
		cpskid := C.CString(*cssl.pskid)
		if cpskid == nil {
			fmt.Printf("\nCould not allocate c mem for psk id")
			return CSSL_APP_ERR_RESOURCES
		}
		C.SSL_set_ex_data(cssl.ssl, 100, unsafe.Pointer(cpskid))
	}
	rval := C.SSL_connect(cssl.ssl)
	if rval == 1 {
		cssl.ssl_up = true
		retval = CSSL_APP_ERR_EOK
		fmt.Printf("\nSSL handshake completed")
	} else {
		app_ret := C.SSL_get_error(cssl.ssl, ret)
		fmt.Printf("\nSSL Connect returned error %d", app_ret)
		retval = CSSLTranslateSSLError(uint8(app_ret))
	}

	return retval
}

func CSSLStoreID(cssl *CSSL, id string) {
	cadmin := C.CString(id)
	if cadmin == nil {
		fmt.Printf("\nCould not store ID")
		return
	}
	C.SSL_set_ex_data(cssl.ssl, 110, unsafe.Pointer(cadmin))
}

func CSSLGetID(cssl *CSSL) string {
	cid := C.SSL_get_ex_data(cssl.ssl, 110)
	if cid != nil {
		id := C.GoString((*C.char)(cid))
		fmt.Printf("\nID is %s", id)
		return id
	}
	return ""
}

func CSSLSetAdmin(cssl *CSSL) {
	cadmin := C.CString(admn_identifier)
	if cadmin == nil {
		fmt.Printf("\nCould not set Admin Flag")
		return
	}
	C.SSL_set_ex_data(cssl.ssl, 100, unsafe.Pointer(cadmin))
}

func CSSLIsAdmin(ssl *C.struct_ssl_st) bool {
	isad := C.SSL_get_ex_data(ssl, 100)
	if isad != nil {
		isAdmin := C.GoString((*C.char)(isad))
		fmt.Printf("\nisad is %s", isAdmin)
		if isAdmin == admn_identifier {
			return true
		}
	} else {
		fmt.Printf("\nnothiing set in 100")
	}
	return false
}

/* Free the CSSL C structures */
func CSSLDelete(cssl *CSSL) {
	if cssl == nil {
		return
	}

	CSSLDeleteFdMap(cssl.fd)

	if cssl.ssl != nil {
		if cssl.ssl_up {
			C.SSL_shutdown(cssl.ssl)
			cssl.ssl_up = false
		}
		pskid := C.SSL_get_ex_data(cssl.ssl, 100)
		id2 := C.SSL_get_ex_data(cssl.ssl, 110)
		if pskid != nil {
			C.free(pskid)
		}
		if id2 != nil {
			C.free(id2)
		}
		C.SSL_free(cssl.ssl)
		cssl.ssl = nil
	}

	if cssl.ssl_ctx != nil {
		C.SSL_CTX_free(cssl.ssl_ctx)
		cssl.ssl_ctx = nil
	}
}

/* SSL Handshake */
func CSSLDoHandshake(cssl *CSSL) uint8 {
	var retval uint8

	if cssl == nil {
		return CSSL_APP_ERR_UNKNOWN
	}

	ret := C.SSL_do_handshake(cssl.ssl)
	if ret == 1 {
		cssl.ssl_up = true
		return CSSL_APP_ERR_EOK
	}

	err := C.SSL_get_error(cssl.ssl, ret)
	retval = CSSLTranslateSSLError(uint8(err))
	fmt.Printf("\nSSL do handshake returned err %d App Err %d", err, retval)

	return retval
}

/* SSL Read returns Entire frame as present in buffer */
func CSSLRead(cssl *CSSL) ([]byte, uint, uint8) {
	var to_read C.int

	if (cssl == nil) || (cssl.ssl_up != true) {
		return nil, 0, CSSL_APP_ERR_UNKNOWN
	}

	C.ERR_clear_error()

	to_read = C.SSL_pending(cssl.ssl)
	if to_read == 0 {
		fmt.Printf("\nSSL read pending returned 0")
		return nil, 0, CSSL_APP_ERR_WANT_READ
	}

	buff := C.malloc((C.size_t(to_read)))
	if buff == nil {
		fmt.Printf("\nCould not allocate buffer for reading data")
		return nil, 0, CSSL_APP_ERR_RESOURCES
	}
	ret := C.SSL_read(cssl.ssl, unsafe.Pointer(buff), to_read)
	if ret < 0 {
		err := C.SSL_get_error(cssl.ssl, ret)
		retval := CSSLTranslateSSLError(uint8(err))
		return nil, 0, retval
	}

	/* we have a buffer read.. lets convert it to a []byte */
	readbuff := C.GoBytes(unsafe.Pointer(buff), ret)
	if readbuff == nil {
		fmt.Printf("\nCould not allocate []byte for read buffer")
		return nil, 0, CSSL_APP_ERR_RESOURCES
	}

	C.free(unsafe.Pointer(buff))
	return readbuff, uint(ret), CSSL_APP_ERR_EOK
}

/* SSL Rean N bytes from the buffer */
func CSSLReadN(cssl *CSSL, to_read uint) ([]byte, uint, uint8) {

	if (cssl == nil) || (cssl.ssl_up != true) {
		return nil, 0, CSSL_APP_ERR_UNKNOWN
	}

	C.ERR_clear_error()

	buff := C.malloc((C.size_t)(to_read))
	if buff == nil {
		fmt.Printf("\nCould not allocate buffer for reading data")
		return nil, 0, CSSL_APP_ERR_RESOURCES
	}
	ret := C.SSL_read(cssl.ssl, unsafe.Pointer(buff), (C.int)(to_read))
	if ret <= 0 {
		err := C.SSL_get_error(cssl.ssl, ret)
		retval := CSSLTranslateSSLError(uint8(err))
		return nil, 0, retval
	}

	/* we have a buffer read.. lets convert it to a []byte */
	readbuff := C.GoBytes(unsafe.Pointer(buff), ret)
	if readbuff == nil {
		fmt.Printf("\nCould not allocate []byte for read buffer")
		return nil, 0, CSSL_APP_ERR_RESOURCES
	}

	C.free(unsafe.Pointer(buff))
	return readbuff, uint(ret), CSSL_APP_ERR_EOK
}

/* SSL Write */
func CSSLWrite(cssl *CSSL, obuff []byte, size uint) uint8 {

	if (cssl == nil) || (cssl.ssl_up != true) || (obuff == nil) {
		return CSSL_APP_ERR_UNKNOWN
	}

	C.ERR_clear_error()

	wr_buff := C.CBytes(obuff)
	if wr_buff == nil {
		fmt.Printf("\nCould not allocate bytes for writing to SSL")
		return CSSL_APP_ERR_RESOURCES
	}

	ret := C.SSL_write(cssl.ssl, (unsafe.Pointer(wr_buff)), (C.int)(size))
	C.free(wr_buff)
	if ret <= 0 {
		err := C.SSL_get_error(cssl.ssl, ret)
		retval := CSSLTranslateSSLError(uint8(err))
		return retval
	}

	return CSSL_APP_ERR_EOK
}

func CSSLSetPSKClientID(cssl *CSSL, id string) bool {
	var newid string

	if (cssl == nil) || (cssl.mode != SSL_MODE_CLIENT) {
		return false
	}

	newid = id
	cssl.pskid = &newid
	return true
}

func IsAdmin(cssl *CSSL) bool {
	return cssl.isadmin
}

//export cssl_go_psk_server_cb
func cssl_go_psk_server_cb(ssl *C.struct_ssl_st, identity *C.char, psk *C.uchar, max_len int) int {
	var psk_key string

	id := C.GoString(identity)
	cid := C.CString(id)
	if cid == nil {
		fmt.Printf("\nCould not store ID")
	}
	C.SSL_set_ex_data(ssl, 110, unsafe.Pointer(cid))

	if cssl_psk_cb == nil {
		fmt.Printf("\n No PSK lookup method specified")
	}
	if CSSLIsAdmin(ssl) {
		if cssl_psk_admin_cb != nil {
			psk_key = cssl_psk_admin_cb(id)
		} else {
			fmt.Printf("\nAdmin Key requested, but handler not set")
			return 0
		}
	} else {
		if cssl_psk_cb != nil {
			psk_key = cssl_psk_cb(id)
		} else {
			fmt.Printf("\nPSK Key requested, but handler not set")
			return 0
		}
	}
	if psk_key == "" {
		fmt.Printf("\nNo PSK key found for ID %s", id)
		return 0
	}
	if len(psk_key) > max_len {
		fmt.Printf("\nPSK Key is too long")
		return 0
	}

	ckey := C.CString(psk_key)
	C.memcpy(unsafe.Pointer(psk), unsafe.Pointer(ckey), C.strlen(ckey))
	C.free(unsafe.Pointer(ckey))
	return len(psk_key)
}

//export cssl_go_psk_client_cb
func cssl_go_psk_client_cb(ssl *C.struct_ssl_st, hint *C.char, id *C.char, max_id_len int, psk *C.char, max_psk int) int {
	pskid := C.SSL_get_ex_data(ssl, 100)
	idlen := C.strlen((*C.char)(pskid))
	if int(idlen) > max_id_len {
		fmt.Printf("\nID is too long")
		return 0
	}
	C.memcpy(unsafe.Pointer(id), unsafe.Pointer(pskid), idlen)
	ids := C.GoString((*C.char)(pskid))
	if cssl_psk_cb == nil {
		fmt.Printf("\nNo PSK lookup method specified")
		return 0
	}
	psk_key := cssl_psk_cb(ids)
	if len(psk_key) > max_psk {
		fmt.Printf("\nPSK Key is too long")
		return 0
	}
	ckey := C.CString(psk_key)
	C.memcpy(unsafe.Pointer(psk), unsafe.Pointer(ckey), C.strlen(ckey))
	C.free(unsafe.Pointer(ckey))
	return len(psk_key)
}

//export cssl_go_msg_cb
func cssl_go_msg_cb(buff *C.char) {
	fmt.Printf("\n%s", buff)
}

//export cssl_go_info_cb
func cssl_go_info_cb(buff *C.char) {
	fmt.Printf("\n%s", buff)
}

//export cssl_go_getdebugflag
func cssl_go_getdebugflag() int {
	if cssl_debug {
		return 1
	}
	return 0
}

/* Set the CA Trust store file */
func CSSLSetTrustStoreFile(cssl *CSSL, certstore string) bool {
	if cssl == nil {
		return false
	}
	ccerts := C.CString(certstore)
	ret := C.SSL_CTX_load_verify_locations(cssl.ssl_ctx, ccerts, nil)
	C.free(unsafe.Pointer(ccerts))
	if int(ret) <= 0 {
		fmt.Printf("\nCould not load TrustStore File")
		return false
	}
	return true
}

/* Set the Private key and Certificate from file */
func CSSLSetPKIInfoFile(cssl *CSSL, keypath, certpath string) bool {
	if cssl == nil {
		return false
	}

	ccertp := C.CString(certpath)
	ckeyp := C.CString(keypath)

	ret1 := C.SSL_CTX_use_certificate_file(cssl.ssl_ctx, ccertp, SSL_FILETYPE_PEM)
	ret2 := C.SSL_CTX_use_PrivateKey_file(cssl.ssl_ctx, ckeyp, SSL_FILETYPE_PEM)
	C.free(unsafe.Pointer(ccertp))
	C.free(unsafe.Pointer(ckeyp))

	if int(ret1) <= 0 {
		fmt.Printf("\nFailed to load certificate from file.")
		return false
	}
	if int(ret2) <= 0 {
		fmt.Printf("\nFailed to load private key from file.")
		return false
	}

	return true
}

/* Set Private Key */
func CSSLSetPrivatekey(cssl *CSSL, key *C.struct_evp_pkey_st) bool {
	if cssl == nil || key == nil {
		return false
	}
	ret := C.SSL_CTX_use_PrivateKey(cssl.ssl_ctx, key)
	if int(ret) != 1 {
		fmt.Printf("\nCould not set PrivateKey")
		return false
	}
	return true
}

/* Set Private key ASN1 */
