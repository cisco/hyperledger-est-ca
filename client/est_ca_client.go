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

package caclient

/*
 * Cisco CA Client
 * Implements the Client Side functionality for the CA
 * Consists of API's For both the Admin and the EST
 * ------------------------------------------------------
 * func InitCAClient()
 * ------------------------------------------------------
 * Function to Initialize the Ca Client. This needs to be
 * called before Calling any of the APIs in this package.
 * ------------------------------------------------------
 */

import (
	"cca"
	"chttp"
	"config"
	"cssl"
	"errors"
	"fmt"
	"net"
	"syscall"
)

/* Taken from the x509 package in go lang DO NOT CHANGE */
const (
	CEST_SIGNATURE_INVALID      = iota
	CEST_SIGNATURE_ECDSA_SHA1   = 9
	CEST_SIGNATURE_ECDSA_SHA256 = 10
	CEST_SIGNATURE_ECDSA_SHA384 = 11
	CEST_SIGNATURE_ECDSA_SHA512 = 12
)

const (
	CurveP256 = cca.CurveP256
	CurveP384 = cca.CurveP384
	CurveP521 = cca.CurveP521
)

var cid string
var cpk string

func getidpass(id string) string {
	if id != "" && id == cid {
		return cpk
	}

	return ""
}

func setidpass(id, pk string) {
	cid = id
	cpk = pk
}

func invalidateidpass() {
	cid = ""
	cpk = ""
}

func getconnectedsocket(ip string, port int) int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("\nError Creating Socket [%s]", err)
		return -1
	}
	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], net.ParseIP(ip).To4())
	err = syscall.Connect(fd, &addr)
	if err != nil {
		fmt.Printf("\nCould not connect to %s:%d [%s]", ip, port, err)
		return -1
	}
	fmt.Printf("\nTCP connection established with %s:%d", ip, port)
	return fd
}

func getconnectedcssl(fd int, id string) *cssl.CSSL {
	cSSL := cssl.CSSLGetNewClient(fd)
	if cSSL == nil {
		fmt.Printf("\nError Creating CSSL object")
		return nil
	}
	/* Let us configure the cipher suite */
	if !cssl.CSSLSetCipher(cSSL, "PSK-AES256-CBC-SHA") {
		fmt.Printf("\nCould not set psk cipher suite")
		return nil
	}
	/* For the client, set the ID as well */
	cssl.CSSLSetPSKClientID(cSSL, id)
	/* Connect to the server */
	retval := cssl.CSSLClientConnect(cSSL)
	if retval != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not complete SSL Handshake")
		fmt.Printf("\nCSSL returned Error %d")
		return nil
	}
	fmt.Printf("\nSSL Handshake successful with the server")
	return cSSL
}

func InitCAClient() {
	cssl.CSSLInit()
	cssl.CSSLSetDebug(true)
	cssl.CSSLSetPSKCb(getidpass)
}

/* Admin APIs */
func GetCaFingerprint(ip string, port int, caname, aid, apk string) (string, int, error) {
	/* First Get the getcafingerprint request */
	httpReq := chttp.GetFingerprintRequest(caname)
	/* Connect to Server */
	cfd := getconnectedsocket(ip, port)
	if cfd < 0 {
		return "", -1, errors.New("TCP Connection Failed")
	}
	defer syscall.Close(cfd)
	/* set ID PASS */
	setidpass(aid, apk)
	defer invalidateidpass()
	/* Do SSL Handshake */
	cSSL := getconnectedcssl(cfd, aid)
	if cSSL == nil {
		return "", -1, errors.New("SSL Handshake Failed")
	}
	fmt.Printf("\nSending Req to the Server\n%s", string(httpReq))
	/* Send the Request to the Server */
	retval := cssl.CSSLWrite(cSSL, httpReq, uint(len(httpReq)))
	if retval != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not Send Request to Server [%d]", retval)
		cssl.CSSLDelete(cSSL)
		return "", -1, errors.New("Req not Sent")
	}
	/* Wait for Response */
	read_bytes, rlen, rerr := cssl.CSSLReadN(cSSL, 2048)
	if rerr != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nGot Error while Reading Data from Server")
		cssl.CSSLDelete(cSSL)
		return "", -1, errors.New("Error on Read")
	}
	fmt.Printf("\nReceived Response From Server [%d bytes]\n%s", rlen, string(read_bytes))
	/* Handle Response */
	Algo, FP, Err := chttp.HandleGetFingerprintResponse(read_bytes)
	if Err != nil {
		fmt.Printf("\nError Handling Response %s", Err)
		cssl.CSSLDelete(cSSL)
		return "", -1, Err
	}
	/* Clean up CSSL */
	cssl.CSSLDelete(cSSL)
	/* we have the reponse */
	fmt.Printf("\nGot FingerPrint and Algo:\n%d,%s", Algo, string(FP))
	return string(FP), Algo, nil
}

func CreateEnrollmentProfile(ip string, port int, aid, apk, eid, esecret,
	caname, caprofile, role string) bool {
	/* Lets get the Create EnrollProfile Request */
	httpReq := chttp.GetCreateEnrolProfRequest(eid, esecret, caprofile, caname, role)
	/* Connect to Server */
	cfd := getconnectedsocket(ip, port)
	if cfd < 0 {
		return false
	}
	defer syscall.Close(cfd)
	/* set ID PASS */
	setidpass(aid, apk)
	defer invalidateidpass()
	/* Do SSL Handshake */
	cSSL := getconnectedcssl(cfd, aid)
	if cSSL == nil {
		return false
	}
	fmt.Printf("\nSending Req to the Server\n%s", string(httpReq))
	/* Send the Request to the Server */
	retval := cssl.CSSLWrite(cSSL, httpReq, uint(len(httpReq)))
	if retval != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not Send Request to Server [%d]", retval)
		cssl.CSSLDelete(cSSL)
		return false
	}
	/* Wait for Response */
	read_bytes, rlen, rerr := cssl.CSSLReadN(cSSL, 2048)
	if rerr != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nGot Error while Reading Data from Server")
		cssl.CSSLDelete(cSSL)
		return false
	}
	/* Clean up SSL */
	cssl.CSSLDelete(cSSL)
	fmt.Printf("\nReceived Response From Server [%d bytes]\n%s", rlen, string(read_bytes))
	/* Handle Response */
	return chttp.HandleCreateEnrolProfResponse(read_bytes)
}

func RevokeCertificate() bool {
	fmt.Printf("\nUnsupported Right now")
	return false
}

/* EST APIs */
func GetCACert(ip string, port int, eid, esec string) (string, error) {
	/* Lets get the GetCACert Request */
	httpReq := chttp.GetGetCACertRequest()
	/* Connect to Server */
	cfd := getconnectedsocket(ip, port)
	if cfd < 0 {
		return "", errors.New("TCP Error")
	}
	defer syscall.Close(cfd)
	/* set ID PASS */
	setidpass(eid, esec)
	defer invalidateidpass()
	/* Do SSL Handshake */
	cSSL := getconnectedcssl(cfd, eid)
	if cSSL == nil {
		return "", errors.New("SSL Error")
	}
	fmt.Printf("\nSending Req to the Server\n%s", string(httpReq))
	/* Send the Request to the Server */
	retval := cssl.CSSLWrite(cSSL, httpReq, uint(len(httpReq)))
	if retval != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not Send Request to Server [%d]", retval)
		cssl.CSSLDelete(cSSL)
		return "", errors.New("Error Writing Data")
	}
	/* Wait for Response */
	read_bytes, rlen, rerr := cssl.CSSLReadN(cSSL, 2048)
	if rerr != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nGot Error while Reading Data from Server")
		cssl.CSSLDelete(cSSL)
		return "", errors.New("Error Reading Data")
	}
	/* Clean up SSL */
	cssl.CSSLDelete(cSSL)
	fmt.Printf("\nReceived Response From Server [%d bytes]\n%s", rlen, string(read_bytes))
	/* handle Response */
	return chttp.HandleGetCACertResponse(read_bytes)
}

func GetIDCert(ip string, port int, eid, esec string, kcurve uint8, sigalgo uint, csr *config.CertAttributes) (string, string, error) {
	/* Generate Key */
	pkey, errKey := cca.GenerateECKey(kcurve)
	if errKey != nil {
		fmt.Printf("\nError Generating key [%s]", errKey)
		return "", "", errKey
	}
	fmt.Printf("\nKey Generated")
	/* Create CSR */
	csrDer, errCsr := cca.GenerateECCSR(csr, pkey, sigalgo)
	if errCsr != nil {
		fmt.Printf("\nError Generating CSR [%s]", errCsr)
		return "", "", errCsr
	}
	fmt.Printf("\nCSR Generated")
	/* Get the HTTP Request */
	httpReq := chttp.GetSimpleEnrollRequest(string(csrDer))
	/* Connect to Server */
	cfd := getconnectedsocket(ip, port)
	if cfd < 0 {
		return "", "", errors.New("TCP Error")
	}
	defer syscall.Close(cfd)
	/* set ID PASS */
	setidpass(eid, esec)
	defer invalidateidpass()
	/* Do SSL Handshake */
	cSSL := getconnectedcssl(cfd, eid)
	if cSSL == nil {
		return "", "", errors.New("SSL Error")
	}
	fmt.Printf("\nSending Req to the Server\n%s", string(httpReq))
	/* Send the Request to the Server */
	retval := cssl.CSSLWrite(cSSL, httpReq, uint(len(httpReq)))
	if retval != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nCould not Send Request to Server [%d]", retval)
		cssl.CSSLDelete(cSSL)
		return "", "", errors.New("Error Sending Req")
	}
	/* Wait for Response */
	read_bytes, rlen, rerr := cssl.CSSLReadN(cSSL, 2048)
	if rerr != cssl.CSSL_APP_ERR_EOK {
		fmt.Printf("\nGot Error while Reading Data from Server")
		cssl.CSSLDelete(cSSL)
		return "", "", errors.New("Error Reading Response")
	}
	/* Clean up SSL */
	cssl.CSSLDelete(cSSL)
	fmt.Printf("\nReceived Response From Server [%d bytes]\n%s", rlen, string(read_bytes))
	/* Let us Handle the Response */
	CertPem, errCert := chttp.HandleSimpleEnrollResponse(read_bytes)
	if errCert != nil {
		fmt.Printf("\nInvalid Cert %s", errCert)
		return "", "", errCert
	}
	/* We have the Cert, lets PEM Encode the Key */
	//pkeyPem := cca.GetECKeyPem(pkey);
	pkeyPem := cca.GetECKeyPemWithAttr(pkey, kcurve)
	//Trim EC PARAMETERS from pkey
	pkeyPem1 := strings.Split(pkeyPem, "\n\n")
	/* Successfully processed everything, lets return */
	fmt.Printf("\nGenerating Key and Fetching Cert Successful")
	return pkeyPem1[1], CertPem, nil
}
