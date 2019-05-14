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

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"github.com/cisco/hyperledger-est-ca/cssl"
)

var example_kpath = "certs2/id2.pem"
var example_certpath = "certs2/id2_cert.pem"
var example_tspath = "certs2/ca-public-cert.pem"

func main() {
	/* Init the OpenSSL Library */
	cssl.CSSLInit()

	cssl.CSSLSetDebug(true)

	/* Create a client socket */
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("\nError in socket creation %d", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	/* Connect to the server over tcp */
	addr := syscall.SockaddrInet4{Port: 2000}
	copy(addr.Addr[:], net.ParseIP("127.0.0.1").To4())
	err = syscall.Connect(fd, &addr)
	if err != nil {
		fmt.Printf("\nCould not complete TCP handshake with the server")
		os.Exit(1)
	}

	/* Create a CSSL server object */
	client_cssl := cssl.CSSLGetNewClient(fd)
	if client_cssl == nil {
		fmt.Printf("\nCould not create a client CSSL object")
		os.Exit(1)
	}

	/* Let us configure the cipher suite */
	if !cssl.CSSLSetCipher(client_cssl, "ECDHE-ECDSA-AES256-SHA") {
		fmt.Printf("\nCould not set EC cipher suite")
		os.Exit(1)
	}

	/* Set the PKIInfo */
	if !cssl.CSSLSetPKIInfoFile(client_cssl, example_kpath, example_certpath) {
		fmt.Printf("\nCould not set the private key/Certficate")
		os.Exit(1)
	}
	/* Set the TrustStore Info */
	if !cssl.CSSLSetTrustStoreFile(client_cssl, example_tspath) {
		fmt.Printf("\nCould not set the trust store")
		os.Exit(1)
	}

	/* Connect to the server */
	retval := cssl.CSSLClientConnect(client_cssl)
	if retval != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not Complete ssl handshake")
		os.Exit(1)
	}
	fmt.Printf("\nSSL handshake complete")
	fmt.Printf("\nSending \"Hello World\" to the server")

	xyz := []byte("Hello World")
	z := xyz[:]

	retval = cssl.CSSLWrite(client_cssl, z, uint(len(z)))
	if retval != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not write data to the server")
		os.Exit(1)
	}

	fmt.Printf("\nWritten data to the server.. waiting on read")
	read_bytes, rlen, rerr := cssl.CSSLReadN(client_cssl, 100)
	if rerr != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not read data from the server")
		os.Exit(1)
	}

	fmt.Printf("\nGot Data from Server of len %d\n", rlen)
	fmt.Println(string(read_bytes[:]))

	/* Lets close this connection */
	cssl.CSSLDelete(client_cssl)

	fmt.Printf("\nFinished handling the connection")
}
