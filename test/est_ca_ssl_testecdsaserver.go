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
	"est/cssl"
	"fmt"
	"net"
	"os"
	"syscall"
)

/* some global test variables */
var test_client_cert_verify bool = true
var example_kpath = "certs2/id1.pem"
var example_certpath = "certs2/id1_cert.pem"
var example_tspath = "certs2/ca-public-cert.pem"

func main() {
	/* Init the OpenSSL Library */
	cssl.CSSLInit()
	/*Set the debug flag to true */
	cssl.CSSLSetDebug(true)

	/* Create a server socket */
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("Error in socket creation %d", err)
		os.Exit(1)
	}
	/* Bind the socket to port 2000 */
	addr := syscall.SockaddrInet4{Port: 2000}
	copy(addr.Addr[:], net.ParseIP("0.0.0.0").To4())
	syscall.Bind(fd, &addr)
	syscall.Listen(fd, 10)
	defer syscall.Close(fd)

	/* Create a CSSL server object */
	server_cssl := cssl.CSSLGetNewServer(fd)
	if server_cssl == nil {
		fmt.Printf("\nCould not create a CSSL object")
		os.Exit(1)
	}
	/* Let us configure the cipher suite */
	if !cssl.CSSLSetCipher(server_cssl, "ECDHE-ECDSA-AES256-SHA") {
		fmt.Printf("\nCould not set ec cipher suite")
		os.Exit(1)
	}

	/* Set the PKIInfo */
	if !cssl.CSSLSetPKIInfoFile(server_cssl, example_kpath, example_certpath) {
		fmt.Printf("\nCould not set the private key/Certficate")
		os.Exit(1)
	}
	/* Set the TrustStore Info */
	if !cssl.CSSLSetTrustStoreFile(server_cssl, example_tspath) {
		fmt.Printf("\nCould not set the trust store")
		os.Exit(1)
	}

	if test_client_cert_verify {
		/* Lets verify the client cert as well */
		cssl.CSSLEnablePeerCertValidation(server_cssl)
	}

	/* Let us handle the Incoming SSL Connections */
	for true {
		fmt.Printf("\nWaiting for new connections\n")
		cfd, _, err := syscall.Accept(fd)
		if err != nil {
			fmt.Printf("\nGot some error while accepting connection")
			os.Exit(1)
		}
		/* We accepted a new connection */
		fmt.Printf("\nAccepted new connection.. starting SSL handshake..")
		client_cssl, retval := cssl.CSSLGetNewServelet(cfd, server_cssl)
		if client_cssl == nil || retval != cssl.CSSL_APP_ERR_EOK {
			fmt.Printf("\nError in SSL handshake")
			continue
		}
		fmt.Printf("\nSSL Handshake done")
		/*
		 * wait for some data to read
		 * Even though blocking sockets are used, we peek and return
		 * if no data is present. Call upon socket event.
		 * if you want blocking behaviour, then use CSSLReadN instead.
		 */
		read_bytes, rlen, ret := cssl.CSSLReadN(client_cssl, 100)
		if ret != cssl.CSSL_APP_ERR_EOK {
			fmt.Printf("\nSSL Read returned error %d", ret)
		} else {
			fmt.Printf("\nSSL read %d bytes\n", rlen)
			fmt.Println(string(read_bytes[:]))
			/* Lets write this data back to the client */
			err := cssl.CSSLWrite(client_cssl, read_bytes, rlen)
			if err != cssl.CSSL_APP_ERR_EOK {
				fmt.Printf("\nCould not write data to client")
			} else {
				fmt.Printf("\nWrote data to client")
			}
		}
		/* Lets close this connection */
		cssl.CSSLDelete(client_cssl)

		fmt.Printf("\nFinished handling the client connection")
	}
}
