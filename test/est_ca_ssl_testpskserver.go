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

/* A func to fetch the PSK using ID */
func example_psk_cb(id string) string {
	/* return cisco123 for now */
	fmt.Printf("\nClient connecting for id %s", id)
	return "cisco123"
}

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
	if !cssl.CSSLSetCipher(server_cssl, "PSK-AES256-CBC-SHA") {
		fmt.Printf("\nCould not set psk cipher suite")
		os.Exit(1)
	}
	/* Since it is PSK, we need a psk callback */
	cssl.CSSLSetPSKCb(example_psk_cb)

	/* we can also set a hint to be sent to the client */
	if !cssl.CSSLSetPSKHint(server_cssl, "hint.domain.com") {
		fmt.Printf("\nCould not set the hint for the server")
		os.Exit(1)
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
