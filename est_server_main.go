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

/*
 * est_server_main.go
 *
 * Syed Arslan Ahmed, Vibuti Shali, Puneeth Rao Lokapalli
 * Cisco Systems, Inc.
 */

package main

import (
	"os"
	"net"
	"flag"
	"strings"
	"syscall"
	"io/ioutil"
	"database/sql"
	"path/filepath"
	"gopkg.in/yaml.v2"
	"github.com/golang/glog"
	"github.com/cisco/hyperledger-est-ca/cca"
	"github.com/cisco/hyperledger-est-ca/cdb"
	"github.com/cisco/hyperledger-est-ca/chttp"
	"github.com/cisco/hyperledger-est-ca/config"
	"github.com/cisco/hyperledger-est-ca/cssl"
	"github.com/cisco/hyperledger-est-ca/cyaml"
)

var cest_db *sql.DB
var cest_admin_id string
var cest_admin_pass string
var cest_admin_cssl *cssl.CSSL
var cest_est_cssl *cssl.CSSL
var cest_admin_listener_fd int = -1
var cest_est_listener_fd int = -1
var cest_epoll_fd int = -1

const (
	MAXEVENTS = 1000
)

const (
	EPOLLET = 1 << 31
)

const (
	FDTYPE_UNKNOWN        = 0
	FDTYPE_LISTENER_ADMIN = 1
	FDTYPE_LISTENER_EST   = 2
	FDTYPE_SERVELET       = 3
)

func get_fd_type(fd int) uint8 {
	if fd == cest_admin_listener_fd {
		return FDTYPE_LISTENER_ADMIN
	} else if fd == cest_est_listener_fd {
		return FDTYPE_LISTENER_EST
	}

	return FDTYPE_UNKNOWN
}

func cest_parse_read_config() {

	var i int
	var yconf cyaml.Config

	args := os.Args
	if len(args) < 2 {
		glog.Errorf("Incorrect Usage. Use s_cest <yaml file path>")
		os.Exit(0)
	}

	// Read and Parse the YAML 
	filename, _ := filepath.Abs(args[1])
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		glog.Errorf("Error while reading the yaml file [%s] - %s", filename, err)
		os.Exit(1)
	}

	err = yaml.Unmarshal(yamlFile, &yconf)
	if err != nil {
		glog.Errorf("Could not unmarshal YAML File - %s", err.Error())
		os.Exit(1)
	}

	// Init Global Config 
	config.InitGlobalConfig()

	// Set Debug mode 
	if strings.ToLower(yconf.Debug) == "true" {
		config.SetDebug(true)
	}

	// Set CRLSize 
	if yconf.Crlsizelimit != 0 {
		config.SetCRLSize(uint32(yconf.Crlsizelimit))
	}

	// Set Crypto Params 
	config.SetCryptoHash(yconf.Crypto.Hash)
	config.SetCryptoEncryptMode(yconf.Crypto.Mode)
	config.SetCryptoEncryption(yconf.Crypto.Encryption)

	// Set Admin interface 
	config.SetAdminInterface(yconf.Admin.Ip, uint16(yconf.Admin.Port))

	// Set EST Interface 
	config.SetESTAuthMethod(yconf.Est.Auth_method)
	config.SetESTAddr(yconf.Est.Ip, uint16(yconf.Est.Port))
	if len(yconf.Est.Tls.Key) > 0 {
		config.SetESTTLSInfo(yconf.Est.Tls.Cert, yconf.Est.Tls.Key, yconf.Est.Tls.Truststore)
	}

	// Set DB Info 
	config.SetDBType(yconf.Db.Type)
	config.SetDBFile(yconf.Db.Datastore)

	// CA profiles 
	config.SetDefaultCAProfile(yconf.Caprofiles.Default)
	for i = 0; i < len(yconf.Caprofiles.Profiles); i++ {
		cp := config.CreateCAProfile(yconf.Caprofiles.Profiles[i].Name)
		config.SetProfileValidity(cp,
			uint64(yconf.Caprofiles.Profiles[i].Validity.Period),
			yconf.Caprofiles.Profiles[i].Validity.Unit)
		config.SetProfileSubjectName(cp,
			yconf.Caprofiles.Profiles[i].Attributes.CN,
			yconf.Caprofiles.Profiles[i].Attributes.O,
			yconf.Caprofiles.Profiles[i].Attributes.C,
			yconf.Caprofiles.Profiles[i].Attributes.OU)
		var isca bool
		if strings.ToLower(yconf.Caprofiles.Profiles[i].Basic_constraints.Is_ca) == "true" {
			isca = true
		} else {
			isca = false
		}
		config.SetProfileBasicAttr(cp, isca,
			uint8(yconf.Caprofiles.Profiles[i].Basic_constraints.Maxpathlength))
	}

	// Set CA Info 
	config.SetDefaultCA(yconf.Ca.Default)
	for i = 0; i < len(yconf.Ca.Ca_list); i++ {
		ca := config.CreateCA(yconf.Ca.Ca_list[i].Name)
		config.SetCAMode(ca, yconf.Ca.Ca_list[i].Mode)
		config.SetCAValidity(ca,
			uint64(yconf.Ca.Ca_list[i].Validity.Period),
			yconf.Ca.Ca_list[i].Validity.Unit)
		config.SetCASubjectName(ca,
			yconf.Ca.Ca_list[i].Csr.Subject_name.CN,
			yconf.Ca.Ca_list[i].Csr.Subject_name.O,
			yconf.Ca.Ca_list[i].Csr.Subject_name.C,
			yconf.Ca.Ca_list[i].Csr.Subject_name.OU)
		config.SetCASubjectAltName(ca,
			yconf.Ca.Ca_list[i].Csr.Subject_alt_name.Ip,
			yconf.Ca.Ca_list[i].Csr.Subject_alt_name.Host)
		config.SetCABasicAttr(ca, uint8(yconf.Ca.Ca_list[i].Csr.Pathlength))
		config.SetCASignatureAlgoritm(ca, yconf.Ca.Ca_list[i].Signature_algorithm)
		config.SetCAKeyInfo(ca, yconf.Ca.Ca_list[i].Key.Type,
			uint16(yconf.Ca.Ca_list[i].Key.Length))
	}
}

func cest_init_db() {
	cest_db = cdb.InitDB(config.GetDBInfo().Dbfile)
	if cest_db == nil {
		glog.Errorf("Failed to init DB")
		os.Exit(2)
	}
	cdb.CreateCaTable(cest_db)
	cdb.CreateCertTable(cest_db)
	cdb.CreateEnrollTable(cest_db)
	cdb.CreateCrlTable(cest_db)
	cdb.CreateCaProfileTable(cest_db)
}

func create_ca_by_name(name string) {
	var caDBItem cdb.CaTable
	serial := 1

	// Lets get the CA config 
	caconfig := config.FindCAByName(name)
	if caconfig == nil {
		glog.Errorf("No such CA configuration found by name %s", name)
		return
	}

	// Initialize caDBItem structure 
	caDBItem.Name = name
	caDBItem.Serial = serial
	caDBItem.EnrollCount = 0
	caDBItem.FpAlgo = int(caconfig.Signature)
	caDBItem.Validity = int(caconfig.Validity)

	// Let us Generate the EC Keypair for this CA 
	// TODO: Right now not taking it from config.. fix this 
	privateKey, err := cca.GenerateECKey(cca.CurveP256)
	if err != nil {
		glog.Errorf("Could not generate keypair [%s]", err.Error())
		return
	}

	// save the private key in base64 encoded string 
	eckeyDer, ret := cca.GetECKeyDer(privateKey)
	if ret != nil {
		glog.Errorf("Could not convert key into der format [%s]", ret.Error())
		return
	}

	caDBItem.Key = cca.Base64Encode(eckeyDer)
	glog.Infof("Generated private key: %s", caDBItem.Key)

	// Generate CSR 
	CaCSR, err2 := cca.GenerateECCSR(&caconfig.Csr, privateKey, uint(caconfig.Signature))
	if err2 != nil {
		glog.Errorf("Could not Generate the CSR")
		return
	}

	// Convert CSR into base64 encoded string and save it for later 
	caDBItem.Csr = cca.Base64Encode(CaCSR)
	glog.Infof("Generated CSR: %s ", caDBItem.Csr)

	// Lets generate the selfsigned certificate 
	cacert, errcert := cca.GenerateSelfSignedCert(&caconfig.Csr, privateKey,
		uint(caconfig.Signature), caconfig.Validity,
		int64(serial))
	if errcert != nil {
		glog.Errorf("Error generating Ca Cert [%s]", errcert.Error())
		return
	}

	// Convert CA Cert to base64 
	caDBItem.Cert = cca.Base64Encode(cacert)
	glog.Infof("Generated SS Cert: %s", caDBItem.Cert)

	// Let us extract the fingerprint 
	fprint, algo := cca.GetCertFingerprint(cacert)
	if algo == 0 {
		glog.Errorf("Could not extract the fingerprint from the cert")
		return
	}

	caDBItem.Fingerprint = cca.Base64Encode(fprint)
	glog.Infof("Extracted Fingerprint: %s", caDBItem.Fingerprint)

	// Lets add this item to the DB 
	cdb.StoreCaItem(cest_db, &caDBItem)
}

func parse_init_ca() {
	// First lets get a list of the CAs configured 
	calist := config.GetCANameList()
	for _, caname := range calist {
		// First lets query the CA from the DB and see if one exists 
		_, count := cdb.SearchCaItem(cest_db, caname)
		if count == 0 {
			glog.Infof("Count = %d.. Creating CA named %s", count, caname)
		} else {
			glog.Infof("Count = %d for CA %s.. continuing", count, caname)
			continue
		}
		create_ca_by_name(caname)
	}
}

func set_admin_creds(id, p string) {
	cest_admin_id = id
	cest_admin_pass = p
}

func get_admin_creds() (string, string) {
	return cest_admin_id, cest_admin_pass
}

func find_admin_idkey(id string) string {
	idc, pass := get_admin_creds()
	if idc != "" && idc == id {
		return pass
	} else {
		return ""
	}
}

func invalidate_admin_idkey() {
	set_admin_creds("", "")
}

func find_est_idkey(id string) string {
	enrollItem, count := cdb.SearchEnrollItem(cest_db, id)
	if count == 0 {
		glog.Infof("\nNo Enrollment profile created for the ID %s yet", id)
		return ""
	}

	return enrollItem.Secret
}

func create_admin_listener() int {
	// FIXME: This Cipher should come from config 
	adminCipher := "ECDHE-ECDSA-AES256-SHA:PSK-AES256-CBC-SHA"
	adminConfig := config.GetAdminInterface()

	// Create a admin server socket 
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		glog.Errorf("Could not create admin socket [%s]", err.Error())
		return -1
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		glog.Errorf("Could not set NonBlocking mode on server")
	}

	// Bind the socket to IP and Port 
	addr := syscall.SockaddrInet4{Port: int(adminConfig.Addr.Port)}
	if adminConfig.Addr.Ip != "" {
		copy(addr.Addr[:], net.ParseIP(adminConfig.Addr.Ip).To4())
	} else {
		copy(addr.Addr[:], net.ParseIP("0.0.0.0").To4())
	}

	syscall.Bind(fd, &addr)

	// Start Listening on this FD 
	syscall.Listen(fd, 10)

	// Get a new CSSL object for Admin 
	cest_admin_cssl = cssl.CSSLGetNewServer(fd)
	if cest_admin_cssl == nil {
		glog.Errorf("Could not create server SSL object for Admin")
		return -1
	}

	// Set Admin Mode 
	cssl.CSSLSetAdminMode(cest_admin_cssl)

	// Let us configure the cipher suite 
	if !cssl.CSSLSetCipher(cest_admin_cssl, adminCipher) {
		glog.Errorf("Could not set the cipher")
		cssl.CSSLDelete(cest_admin_cssl)
		cest_admin_cssl = nil
		return -1
	}

	// Set the PSK Server Callback 
	cssl.CSSLSetAdminPSKCb(find_admin_idkey)
	cest_admin_listener_fd = fd

	return fd
}

func create_est_listener() int {
	// FIXME: This Cipher should come from config 
	cipher := "PSK-AES256-CBC-SHA"
	estConfig := config.GetESTInterface()

	// Create an est server socket 
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		glog.Errorf("Could not create admin socket [%s]", err.Error())
		return -1
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		glog.Errorf("Could not set NonBlocking mode on server")
	}

	// Bind the socket to IP and Port 
	addr := syscall.SockaddrInet4{Port: int(estConfig.Addr.Port)}
	if estConfig.Addr.Ip != "" {
		copy(addr.Addr[:], net.ParseIP(estConfig.Addr.Ip).To4())
	} else {
		copy(addr.Addr[:], net.ParseIP("0.0.0.0").To4())
	}
	syscall.Bind(fd, &addr)

	// Start Listening on this FD 
	syscall.Listen(fd, 10)

	// Get a new CSSL object for Admin 
	cest_est_cssl = cssl.CSSLGetNewServer(fd)
	if cest_est_cssl == nil {
		glog.Errorf("Could not create server SSL object for Admin")
		return -1
	}

	// Let us configure the cipher suite 
	if !cssl.CSSLSetCipher(cest_est_cssl, cipher) {
		glog.Errorf("Could not set the cipher")
		cssl.CSSLDelete(cest_est_cssl)
		cest_est_cssl = nil
		return -1
	}

	// Set the PSK Server Callback 
	cssl.CSSLSetPSKCb(find_est_idkey)
	cest_est_listener_fd = fd

	return fd
}

func add_fd_to_epoll(efd, fd int) bool {
	var event syscall.EpollEvent

	event.Events = (syscall.EPOLLIN)
	event.Fd = int32(fd)

	e := syscall.EpollCtl(efd, syscall.EPOLL_CTL_ADD, fd, &event)
	if e != nil {
		glog.Errorf("Could not add fd to epoll [%s]", e)
		return false
	}

	return true
}

func handle_admin_listener_event(lfd int) {
	var cfd int
	var err error

	glog.Infof("Got new event on the admin Interface")
	for {
		cfd, _, err = syscall.Accept(lfd)
		if err != nil {
			glog.Errorf("Err accepting connection [%s]", err.Error())
			return
		}
		glog.Infof("Accepted new connection %d", cfd)
		client_cssl, retval := cssl.CSSLGetNewServelet(cfd, cest_admin_cssl)
		if client_cssl == nil || retval != cssl.CSSL_APP_ERR_EOK {
			glog.Errorf("Could not Complete SSL handshake")
			glog.Errorf("Client_CSSL: %p retval %d", client_cssl, retval)
			continue
		}

		// Add FD to Epoll 
		add_fd_to_epoll(cest_epoll_fd, cfd)
		glog.Infof("SSL handshake Complete.. Trying to read any pending data")
		//handle_client_event(cfd);
	}
}

func handle_est_listener_event(lfd int) {
	var cfd int
	var err error

	glog.Infof("Got new event on the est Interface")
	for {
		cfd, _, err = syscall.Accept(lfd)
		if err != nil {
			glog.Errorf("Err accepting connection [%s]", err.Error())
			return
		}

		glog.Infof("Accepted new connection %d", cfd)
		client_cssl, retval := cssl.CSSLGetNewServelet(cfd, cest_est_cssl)
		if client_cssl == nil || retval != cssl.CSSL_APP_ERR_EOK {
			glog.Errorf("Could not Complete SSL handshake")
			continue
		}

		add_fd_to_epoll(cest_epoll_fd, cfd)
		glog.Infof("SSL handshake Complete.. Trying to read any pending data")
		//handle_client_event(cfd);
	}

}

func handle_client_event(cfd int) {
	cSSL := cssl.CSSLGetByFd(cfd)

	glog.Infof("cSSL is %p in handle client ev", cSSL)

	if cSSL == nil {
		return
	}

	// we have a valid CSSL object.. lets see if we have Data 
	rdata, rlen, err := cssl.CSSLReadN(cSSL, 2048)
	if err == cssl.CSSL_APP_ERR_EOK {
		glog.Infof("Read %d bytes from the client... Data read:", rlen)
		if cssl.IsAdmin(cSSL) {
			resp := chttp.HttpHandleAdminRequest(rdata)
			if len(resp) == 0 {
				return
			}
			// Write Response to the Connection 
			retval := cssl.CSSLWrite(cSSL, resp, uint(len(resp)))
			if retval != cssl.CSSL_APP_ERR_EOK {
				glog.Errorf("Could not Successfully write Data")
			}
		} else {
			id := cssl.CSSLGetID(cSSL)
			resp := chttp.HttpHandleESTRequest(rdata, id)
			if len(resp) == 0 {
				return
			}
			// Write Response to the Connection 
			retval := cssl.CSSLWrite(cSSL, resp, uint(len(resp)))
			if retval != cssl.CSSL_APP_ERR_EOK {
				glog.Errorf("Could not Successfully write Data")
			}
		}
	} else if err == cssl.CSSL_APP_ERR_WANT_READ ||
		err == cssl.CSSL_APP_ERR_WANT_WRITE {
		glog.Errorf("No More Data to read")
		return
	} else if err == cssl.CSSL_APP_ERR_UNKNOWN {
		glog.Errorf("Unknown error occured on the client connection.. closing")
		cssl.CSSLDelete(cSSL)
		syscall.Close(cfd)
		return
	} else if err == cssl.CSSL_APP_ERR_SYSCALL {
		glog.Errorf("Peer Closed Connection")
		cssl.CSSLDelete(cSSL)
		syscall.Close(cfd)
		return
	} else {
		glog.Errorf("err = %d", err)
		return
	}

}

func init_engine() {
	var events [MAXEVENTS]syscall.EpollEvent

	// First Create the epoll for the engine 
	epoll_fd, err := syscall.EpollCreate1(0)
	if err != nil {
		glog.Errorf("Could not create epoll for engine [%s]", err.Error())
	}
	cest_epoll_fd = epoll_fd

	// Create Admin Listener and add it to epoll 
	adminfd := create_admin_listener()
	if adminfd <= 0 {
		glog.Errorf("Could not Create Admin Listener")
		return
	}

	ret := add_fd_to_epoll(epoll_fd, adminfd)
	if !ret {
		glog.Errorf("Could not add Admin FD to Epoll")
		return
	}

	glog.Infof("Started Admin Listener...")

	// create EST Listener and add it to epoll 
	estfd := create_est_listener()
	if estfd <= 0 {
		glog.Errorf("Could not create EST Listener")
		return
	}

	ret = add_fd_to_epoll(epoll_fd, estfd)
	if !ret {
		glog.Errorf("Could not add EST FD to EPOLL")
		return
	}
	glog.Infof("\nStarted the EST Interface.. We are ready to Rock and Roll")

	for {
		nevents, e := syscall.EpollWait(epoll_fd, events[:], -1)
		if e != nil {
			glog.Errorf("Error [%s] in epoll", e.Error())
			continue
		}

		for i := 0; i < nevents; i++ {
			if ((events[i].Events & syscall.EPOLLHUP) == syscall.EPOLLHUP) ||
				((events[i].Events & syscall.EPOLLERR) == syscall.EPOLLERR) {
				glog.Errorf("Error on Socket %d closing it")
				cSSL := cssl.CSSLGetByFd(int(events[i].Fd))
				cssl.CSSLDelete(cSSL)
				syscall.Close(int(events[i].Fd))
				continue
			}

			switch get_fd_type(int(events[i].Fd)) {
			case FDTYPE_LISTENER_ADMIN:
				glog.Infof("Got Admin Listener Event")
				handle_admin_listener_event(int(events[i].Fd))
			case FDTYPE_LISTENER_EST:
				glog.Infof("Got Event on EST Listener")
				handle_est_listener_event(int(events[i].Fd))
			default:
				glog.Infof("Got Event on Client FD")
				handle_client_event(int(events[i].Fd))
			}
		}
	}
}

func main() {

	flag.Parse()
	flag.Set("logtostderr", "true")

	un := os.Getenv("EST_CA_ADMIN_NAME")
	if (un == "") {
		glog.Error("Missing environment variable 'EST_CA_ADMIN_NAME'")
		os.Exit(-1)
	}

	p := os.Getenv("EST_CA_ADMIN_PASSWD")
	if (p == "") {
		glog.Error("Missing environment variable 'EST_CA_ADMIN_PASSWD'")
		os.Exit(-1)
	}

	// Initialize cssl library 
	cssl.CSSLInit()

	//Set the debug flag to true 
	cssl.CSSLSetDebug(true)

	// read and parse the yaml config 
	cest_parse_read_config()

	// init DB 
	cest_init_db()

	// Lets print the config and check if everything is ok 
	config.PrintConfigInfo()

	// Now lets parse the config ca's and create them 
	parse_init_ca()

	set_admin_creds(un, p)

	// Init the Engine 
	init_engine()

	glog.Infof("\nServer Exiting...\n")
}
