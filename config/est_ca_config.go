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
 * Public Interfaces:
 *
 * Init Config
 * ---------------------------------------------------
 * func InitGlobalConfig()
 * Call for initializing/resetting Config to defaults
 * ---------------------------------------------------
 * General Purpose APIs
 * ---------------------------------------------------
 * func PrintConfigInfo()
 * func GetLDAPInfo() *LDAPInfo
 * func GetDBInfo() *DBInfo
 * func GetESTInterface() *ESTInterface
 * func GetAdminInterface() *AdminInterface
 * func GetCRLSize() uint32
 * func GetDebugFlag() bool
 * ---------------------------------------------------
 * Set CRL Size and Debug
 * ---------------------------------------------------
 * func SetCRLSize(s uint32)
 * func SetDebug(sense bool)
 * ---------------------------------------------------
 * Set Crypto Info
 * ---------------------------------------------------
 * func SetCryptoHash(hash string) bool
 * func SetCryptoEncryptMode(enc string) bool
 * func SetCryptoEncryption(enc string) bool
 * ---------------------------------------------------
 * Set Admin Interface
 * ---------------------------------------------------
 * func SetAdminInterface(ip string, port uint16) bool
 * ---------------------------------------------------
 * Set EST Interface
 * ---------------------------------------------------
 * func SetESTTLSInfo(id, key, tstore string) bool
 * func SetESTAuthMethod(auth string) bool
 * func SetESTAddr(ip string, port uint16) bool
 * ---------------------------------------------------
 * Set LDAP Info
 * ---------------------------------------------------
 * func SetLDAPTLSInfo(id, key, tstore string) bool
 * func SetLDAPAddr(ip string, port uint16) bool
 * func SetLDAPURL(url string) bool
 * ---------------------------------------------------
 * Set DB info
 * ---------------------------------------------------
 * func SetDBURL(url string) bool
 * func SetDBIP(ip string, port uint16) bool
 * func SetDBTLSInfo(id, key, tstore string) bool
 * func SetDBCredentials(uname string, pass string) bool
 * func SetDBFile(file string) bool
 * func SetDBType(t string) bool
 * ---------------------------------------------------
 * Set CA Profile
 * ---------------------------------------------------
 * func CreateCAProfile(name string) *CAProfile
 * func DeleteCAProfilebyName(name string)
 * func FindCAProfileByName(name string) *CAProfile
 * func SetDefaultCAProfile(name string) bool
 * func SetProfileValidity(prof *CAProfile, val uint64, unit string) bool
 * func SetProfileBasicAttr(prof *CAProfile, isca bool, maxpath int) bool
 * func SetProfileSubjectAltName(prof *CAProfile, ip, host, string) bool
 * func SetProfileSubjectName(prof *CAProfile, cn, o, c, ou string) bool
 * ---------------------------------------------------
 * Set CA
 * ---------------------------------------------------
 * func DeleteCAbyName(name string)
 * func CreateCA(name string) *CA
 * func FindCAByName(name string) *CA
 * func GetCANameList() []CA
 * func SetCASignatureAlgoritm(ca *CA, algo string) bool
 * func SetCAKeyInfo(ca *CA, ktype string, klen int) bool
 * func SetCABasicAttr(ca *CA, maxpath int) bool
 * func SetCASubjectAltName(ca *CA, ip, host, string) bool
 * func SetCASubjectName(ca *CA, cn, o, c, ou string) bool
 * func SetCAValidity(ca *CA, val uint64, unit string) bool
 * func SetCACRLPath(ca *CA, crlpath string) bool
 * func SetCACertPath(ca *CA, cpath, kpath, chainpath string) bool
 * func SetCAMode(ca *CA, camode string) bool
 * func SetDefaultCA(name string) bool
 * func GetDefaultCA() string
 * func SetCATLSInfo(ca *CA, id, key, tstore string) bool
 * func SetEnrollParameter(ca *CA, fingerprint, uname, passwd string) bool
 * func SetParentCAAuthMode(ca *CA, mode string) bool {
 * func SetParentCAURL(ca *CA, url string) bool
 * func SetParentCAIP(ca *CA, ip string, port uint16) bool
 * ---------------------------------------------------
 */

package config

import (
	"fmt"
	"strings"
)

// Enum Definitions 
const (
	CEST_ENCRYPTION_INVALID = iota
	CEST_ENCRYPTION_AES128
	CEST_ENCRYPTION_AES256
)

const (
	CEST_STR_ENCRYPTION_AES128 = "aes128"
	CEST_STR_ENCRYPTION_AES256 = "aes256"
)

const (
	CEST_MODE_INVALID = iota
	CEST_MODE_CBC
	CEST_MODE_GCM
)

const (
	CEST_STR_ENC_MODE_CBC = "cbc"
	CEST_STR_ENC_MODE_GCM = "gcm"
)

const (
	CEST_HASH_INVALID = iota
	CEST_HASH_SHA1
	CEST_HASH_SHA256
	CEST_HASH_SHA384
	CEST_HASH_SHA512
)

const (
	CEST_STR_HASH_SHA1   = "sha1"
	CEST_STR_HASH_SHA256 = "sha256"
	CEST_STR_HASH_SHA384 = "sha384"
	CEST_STR_HASH_SHA512 = "sha512"
)

const (
	CEST_ENGINE_INVALID = iota
	CEST_ENGINE_SW
	CEST_ENGINE_CUSTOM
)

const (
	CEST_STR_ENGINE_SW = "sw"
)

const (
	CEST_DBTYPE_INVALID = iota
	CEST_DBTYPE_SQLLITE
	CEST_DBTYPE_MYSQL
)

const (
	CEST_STR_DBTYPE_SQLLITE = "sqllite"
	CEST_STR_DBTYPE_MYSQL   = "mysql"
)

const (
	CEST_AUTH_METHOD_INVALID = iota
	CEST_AUTH_METHOD_TLSPSK
	CEST_AUTH_METHOD_CERTAUTH
	CEST_AUTH_METHOD_HTTPBASICAUTH
)

const (
	CEST_STR_AUTH_TLSPSK        = "tls-psk"
	CEST_STR_AUTH_CERTAUTH      = "cert-auth"
	CEST_STR_AUTH_HTTPBASICAUTH = "http-basic-auth"
)

const (
	CEST_KEYTYPE_INVALID = iota
	CEST_KEYTYPE_RSA
	CEST_KEYTYPE_ECDSA
)

const (
	CEST_STR_KEYTYPE_RSA   = "rsa"
	CEST_STR_KEYTYPE_ECDSA = "ecdsa"
)

const (
	CEST_CA_MODE_INVALID = iota
	CEST_CA_MODE_ROOT
	CEST_CA_MODE_SUBCA
)

const (
	CEST_STR_CA_MODE_ROOT  = "ca"
	CEST_STR_CA_MODE_SUBCA = "subca"
)

const (
	CEST_VALIDITY_UNIT_DAYS  = "day"
	CEST_VALIDITY_UNIT_HOURS = "hour"
	CEST_VALIDITY_UNIT_YEARS = "year"
)

// Taken from the x509 package in go lang 
const (
	CEST_SIGNATURE_INVALID      = iota
	CEST_SIGNATURE_ECDSA_SHA1   = 9
	CEST_SIGNATURE_ECDSA_SHA256 = 10
	CEST_SIGNATURE_ECDSA_SHA384 = 11
	CEST_SIGNATURE_ECDSA_SHA512 = 12
)

const (
	CEST_STR_SIGNATURE_ECDSA_SHA1   = "ecdsa-with-sha1"
	CEST_STR_SIGNATURE_ECDSA_SHA256 = "ecdsa-with-sha256"
	CEST_STR_SIGNATURE_ECDSA_SHA384 = "ecdsa-with-sha384"
	CEST_STR_SIGNATURE_ECDSA_SHA512 = "ecdsa-with-sha512"
)

// Defaults for the configuration 
const CEST_ENCRYPTION_DEFAULT = CEST_ENCRYPTION_AES128
const CEST_ENCRYPTION_MODE_DEFAULT = CEST_MODE_CBC
const CEST_HASH_DEFAULT = CEST_HASH_SHA256
const CEST_ENGINE_DEFAULT = CEST_ENGINE_SW
const CEST_DBTYPE_DEFAULT = CEST_DBTYPE_SQLLITE
const CEST_DBFILE_DEFAULT = "est_ca_database.db"
const CEST_AUTH_METHOD_DEFAULT = CEST_AUTH_METHOD_TLSPSK
const CEST_KEYTYPE_DEFAULT = CEST_KEYTYPE_ECDSA
const CEST_CA_MODE_DEFAULT = CEST_CA_MODE_ROOT
const CEST_SIGNATURE_DEFAULT = CEST_SIGNATURE_ECDSA_SHA512

const CEST_KEYLENGTH_DEFAULT = 512
const CEST_CA_VALIDITY_DEFAULT = 43830    // In hours 
const CEST_CLIENT_VALIDITY_DEFAULT = 8766 // In hours 
const CEST_CRLSIZE_DEFAULT = 512000

type KeyInfo struct {
	Ktype  uint8
	Length uint16
}

type Crypto struct {
	Encryption uint8
	Mode       uint8
	Hash       uint8
	Engine     uint8
}

type Address struct {
	Ip   string
	Port uint16
	Url  string
}

type TLSInfo struct {
	Enabled    bool
	Idcertpath string
	Keypath    string
	Tstorepath string
}

type CertSubjectName struct {
	Cn string
	O  string
	C  string
	Ou string
}

type CertSubjectAltName struct {
	Ip   string
	Host string
}

type CertBasicAttr struct {
	Isca       bool
	Maxpathlen uint8
}

type CertAttributes struct {
	Subname    CertSubjectName
	Subaltname CertSubjectAltName
	Basicattr  CertBasicAttr
}

type AdminInterface struct {
	Addr Address
}

type ESTInterface struct {
	Addr       Address
	Authmethod uint8
	Tls        TLSInfo
}

type DBInfo struct {
	Dbtype uint8
	Dbfile string
	Addr   Address
	Uname  string
	Passwd string
	Tls    TLSInfo
}

type LDAPInfo struct {
	Enabled bool
	Addr    Address
	Tls     TLSInfo
}

type CAProfile struct {
	Name     string
	Attr     CertAttributes
	Validity uint64
	next     *CAProfile
}

type CAProfileList struct {
	head         *CAProfile
	count        uint32
	Default_prof string
}

type ParentCAInfo struct {
	Addr          Address
	Authmode      uint8
	Cafingerprint string
	Enrollid      string
	Passwd        string
	Tls           TLSInfo
}

type CA struct {
	Name      string
	Mode      uint8
	Certpath  string
	Keypath   string
	Chainpath string
	Crlpath   string
	Validity  uint64
	Csr       CertAttributes
	Key       KeyInfo
	Signature uint8
	Parent    ParentCAInfo
	next      *CA
}

type CAList struct {
	head      *CA
	count     uint32
	Defaultca string
}

type CESTConfig struct {
	debug      bool
	crlsize    uint32
	crypto     Crypto
	admin      AdminInterface
	est        ESTInterface
	db         DBInfo
	ldap       LDAPInfo
	caprofiles CAProfileList
	calist     CAList
}

// Global Config Structure 
var cest_global_config CESTConfig

// Interfaces for Config manipulation

// Returns the Global Config Block 
func GetGlobalConfig() *CESTConfig {
	return (&cest_global_config)
}

// Set the defaults in a config structure 
func SetConfigDefaults(conf *CESTConfig) {
	if conf == nil {
		return
	}

	// Set CRL SIZE 
	conf.crlsize = CEST_CRLSIZE_DEFAULT

	// Set Crypto Parameters 
	conf.crypto.Encryption = CEST_ENCRYPTION_DEFAULT
	conf.crypto.Mode = CEST_ENCRYPTION_MODE_DEFAULT
	conf.crypto.Hash = CEST_HASH_DEFAULT
	conf.crypto.Engine = CEST_ENGINE_DEFAULT

	// Set DB defaults 
	conf.db.Dbtype = CEST_DBTYPE_DEFAULT
	conf.db.Dbfile = CEST_DBFILE_DEFAULT
}

// Initializes the global config to defaults 
func InitGlobalConfig() {

	SetConfigDefaults(GetGlobalConfig())

}

// Set Debug mode 
func SetDebug(sense bool) {

	GetGlobalConfig().debug = sense
}

// Set the CRL size 
func SetCRLSize(s uint32) {
	GetGlobalConfig().crlsize = s
}

// Get Crypto Encryption type from String 
func GetCryptoEncryptionType(t string) uint8 {
	switch strings.ToLower(t) {
	case CEST_STR_ENCRYPTION_AES128:
		return CEST_ENCRYPTION_AES128
	case CEST_STR_ENCRYPTION_AES256:
		return CEST_ENCRYPTION_AES256
	default:
		return CEST_ENCRYPTION_INVALID
	}
}

// Get Encryption Mode type 
func GetCryptoEncryptionModeType(t string) uint8 {
	switch strings.ToLower(t) {
	case CEST_STR_ENC_MODE_CBC:
		return CEST_MODE_CBC
	case CEST_STR_ENC_MODE_GCM:
		return CEST_MODE_GCM
	default:
		return CEST_MODE_INVALID
	}
}

// Get Hash type 
func GetCryptoHashType(t string) uint8 {
	switch strings.ToLower(t) {
	case CEST_STR_HASH_SHA1:
		return CEST_HASH_SHA1
	case CEST_STR_HASH_SHA256:
		return CEST_HASH_SHA256
	case CEST_STR_HASH_SHA384:
		return CEST_HASH_SHA384
	case CEST_STR_HASH_SHA512:
		return CEST_HASH_SHA512
	default:
		return CEST_HASH_INVALID
	}
}

// Get Auth method type 
func GetESTAuthMethod(t string) uint8 {
	switch strings.ToLower(t) {
	case CEST_STR_AUTH_TLSPSK:
		return CEST_AUTH_METHOD_TLSPSK
	case CEST_STR_AUTH_CERTAUTH:
		return CEST_AUTH_METHOD_CERTAUTH
	case CEST_STR_AUTH_HTTPBASICAUTH:
		return CEST_AUTH_METHOD_HTTPBASICAUTH
	default:
		return CEST_AUTH_METHOD_INVALID
	}
}

// Get the DB type from string 
func GetDBType(t string) uint8 {
	switch strings.ToLower(t) {
	case CEST_STR_DBTYPE_SQLLITE:
		return CEST_DBTYPE_SQLLITE
	case CEST_STR_DBTYPE_MYSQL:
		return CEST_DBTYPE_MYSQL
	default:
		return CEST_DBTYPE_INVALID
	}
}

// Set Crypto Encryption 
func SetCryptoEncryption(enc string) bool {
	var x uint8

	x = GetCryptoEncryptionType(enc)
	if x != CEST_ENCRYPTION_INVALID {
		GetGlobalConfig().crypto.Encryption = x
		return true
	}

	return false
}

// Set Crypto Hash 
func SetCryptoEncryptMode(enc string) bool {
	var x uint8

	x = GetCryptoEncryptionModeType(enc)
	if x != CEST_MODE_INVALID {
		GetGlobalConfig().crypto.Mode = x
		return true
	}

	return false
}

// Set the crypto hash 
func SetCryptoHash(hash string) bool {
	var x uint8

	x = GetCryptoHashType(hash)
	if x != CEST_HASH_INVALID {
		GetGlobalConfig().crypto.Hash = x
		return true
	}

	return false
}

// Set Admin Interface 
func SetAdminInterface(ip string, port uint16) bool {
	conf := GetGlobalConfig()
	conf.admin.Addr.Ip = ip
	conf.admin.Addr.Port = port

	return true
}

// Set EST Interface 
func SetESTAddr(ip string, port uint16) bool {
	conf := GetGlobalConfig()
	conf.est.Addr.Ip = ip
	conf.est.Addr.Port = port

	return true
}

// Set EST Auth Method 
func SetESTAuthMethod(auth string) bool {
	var x uint8

	x = GetESTAuthMethod(auth)
	if x != CEST_AUTH_METHOD_INVALID {
		GetGlobalConfig().est.Authmethod = x
		return true
	}

	return false
}

// Set EST TLS params 
func SetESTTLSInfo(id, key, tstore string) bool {
	conf := GetGlobalConfig()
	conf.est.Tls.Enabled = true
	conf.est.Tls.Idcertpath = id
	conf.est.Tls.Keypath = key
	conf.est.Tls.Tstorepath = tstore

	return true
}

// Set LDAP URL info 
func SetLDAPURL(url string) bool {
	conf := GetGlobalConfig()
	conf.ldap.Enabled = true
	conf.ldap.Addr.Url = url

	return true
}

// Set LDAP IP/Port 
func SetLDAPAddr(ip string, port uint16) bool {
	conf := GetGlobalConfig()
	conf.ldap.Enabled = true
	conf.ldap.Addr.Ip = ip
	conf.ldap.Addr.Port = port

	return true
}

// Set LDAP TLS info 
func SetLDAPTLSInfo(id, key, tstore string) bool {
	conf := GetGlobalConfig()
	conf.ldap.Tls.Enabled = true
	conf.ldap.Tls.Idcertpath = id
	conf.ldap.Tls.Keypath = key
	conf.ldap.Tls.Tstorepath = tstore

	return true
}

// Set DB type 
func SetDBType(t string) bool {
	var x uint8

	x = GetDBType(t)
	if x != CEST_DBTYPE_INVALID {
		GetGlobalConfig().db.Dbtype = x
		return true
	}

	return false
}

// Set DB Filename 
func SetDBFile(file string) bool {
	GetGlobalConfig().db.Dbfile = file

	return true
}

// Set DB credentials 
func SetDBCredentials(uname string, pass string) bool {
	conf := GetGlobalConfig()
	conf.db.Uname = uname
	conf.db.Passwd = pass

	return true
}

// Set DB IP/Port 
func SetDBIP(ip string, port uint16) bool {
	conf := GetGlobalConfig()
	conf.db.Addr.Ip = ip
	conf.db.Addr.Port = port

	return true
}

// Set DB URL 
func SetDBURL(url string) bool {
	GetGlobalConfig().db.Addr.Url = url

	return true
}

// Set DB TLS Info 
func SetDBTLSInfo(id, key, tstore string) bool {
	conf := GetGlobalConfig()
	conf.db.Tls.Enabled = true
	conf.db.Tls.Idcertpath = id
	conf.db.Tls.Keypath = key
	conf.db.Tls.Tstorepath = tstore

	return true
}

// Set Default CA Profile if configured 
func SetDefaultCAProfile(name string) bool {
	// Add validation for default later 
	GetGlobalConfig().caprofiles.Default_prof = name

	return true
}

// Get Default CA Profile Name 
func GetDefaultCAProfile() string {
	return GetGlobalConfig().caprofiles.Default_prof
}

// Set Default CA if configured 
func SetDefaultCA(name string) bool {
	// Add validation for default later 
	GetGlobalConfig().calist.Defaultca = name

	return true
}

// Get Default CA 
func GetDefaultCA() string {
	return GetGlobalConfig().calist.Defaultca
}

// Find CA Profile by name 
func FindCAProfileByName(name string) *CAProfile {
	var i uint32
	var prof *CAProfile

	conf := GetGlobalConfig()
	prof = conf.caprofiles.head
	for i = 0; i < conf.caprofiles.count; i++ {
		if (prof != nil) && (prof.Name == name) {
			return prof
		}
		prof = prof.next
	}

	return nil
}

// Find CA by name 
func FindCAByName(name string) *CA {
	var i uint32
	var ca *CA

	conf := GetGlobalConfig()
	ca = conf.calist.head
	for i = 0; i < conf.calist.count; i++ {
		if (ca != nil) && (ca.Name == name) {
			return ca
		}
		ca = ca.next
	}

	return nil
}

// Create new ca profile object by name 
func CreateCAProfile(name string) *CAProfile {

	var caprof *CAProfile
	conf := GetGlobalConfig()

	// Does it exist? 
	caprof = FindCAProfileByName(name)
	if caprof != nil {
		return caprof
	}

	caprof = new(CAProfile)
	caprof.Name = name

	if conf.caprofiles.head == nil {
		conf.caprofiles.head = caprof
	} else {
		caprof.next = conf.caprofiles.head
		conf.caprofiles.head = caprof
	}

	conf.caprofiles.count++

	// Set Defaults 
	caprof.Validity = CEST_CLIENT_VALIDITY_DEFAULT

	return caprof
}

// GetCANameList 
func GetCANameList() []string {
	var ca *CA
	var i uint32
	var canamearray [100]string

	conf := GetGlobalConfig()
	ca = conf.calist.head

	for i = 0; i < conf.calist.count; i++ {
		canamearray[i] = ca.Name
		ca = ca.next
	}

	list := canamearray[:i]
	return list
}

// Create new ca object by name 
func CreateCA(name string) *CA {

	var ca *CA
	conf := GetGlobalConfig()

	// Does it exist? 
	ca = FindCAByName(name)
	if ca != nil {
		return ca
	}

	ca = new(CA)
	ca.Name = name

	if conf.calist.head == nil {
		conf.calist.head = ca
	} else {
		ca.next = conf.calist.head
		conf.calist.head = ca
	}

	conf.calist.count++

	// Set defaults for the ca 
	ca.Mode = CEST_CA_MODE_DEFAULT
	ca.Validity = CEST_CA_VALIDITY_DEFAULT
	ca.Signature = CEST_SIGNATURE_DEFAULT
	ca.Key.Ktype = CEST_KEYTYPE_DEFAULT
	ca.Key.Length = CEST_KEYLENGTH_DEFAULT
	ca.Csr.Basicattr.Isca = true

	return ca
}

// Set Profile Subjectname 
func SetProfileSubjectName(prof *CAProfile, cn, o, c, ou string) bool {
	if prof == nil {
		return false
	}

	prof.Attr.Subname.Cn = cn
	prof.Attr.Subname.O = o
	prof.Attr.Subname.C = c
	prof.Attr.Subname.Ou = ou

	return true
}

// Set Profile Sub Alt name 
func SetProfileSubjectAltName(prof *CAProfile, ip, host string) bool {
	if prof == nil {
		return false
	}

	prof.Attr.Subaltname.Ip = ip
	prof.Attr.Subaltname.Host = host

	return true
}

// Set profile basic Attributes 
func SetProfileBasicAttr(prof *CAProfile, isca bool, maxpath uint8) bool {
	if prof == nil {
		return false
	}

	prof.Attr.Basicattr.Isca = isca
	prof.Attr.Basicattr.Maxpathlen = maxpath

	return true
}

// find validity in hours given units and number 
func GetValidityInHours(val uint64, unit string) uint64 {
	var factor uint64
	switch strings.ToLower(unit) {
	case CEST_VALIDITY_UNIT_HOURS:
		factor = 1
	case CEST_VALIDITY_UNIT_DAYS:
		factor = 24
	case CEST_VALIDITY_UNIT_YEARS:
		factor = 8766
	default:
		factor = 0
	}

	return (val * factor)
}

// Set validity for profile 
func SetProfileValidity(prof *CAProfile, val uint64, unit string) bool {
	var valhours uint64

	if prof == nil {
		return false
	}

	valhours = GetValidityInHours(val, unit)
	if valhours == 0 {
		return false
	}

	prof.Validity = valhours

	return true
}

// Delete CA Profile 
func DeleteCAProfilebyName(name string) {
	var caprof *CAProfile
	conf := GetGlobalConfig()

	// Does it exist? 
	caprof = FindCAProfileByName(name)
	if caprof == nil {
		return
	}

	conf.caprofiles.head = caprof.next
	conf.caprofiles.count--
}

// Delete CA Config 
func DeleteCAbyName(name string) {
	var ca *CA
	conf := GetGlobalConfig()

	// Does it exist? 
	ca = FindCAByName(name)
	if ca == nil {
		return
	}

	conf.calist.head = ca.next
	conf.calist.count--
}

// Get CA mode type 
func GetCAModeType(s string) uint8 {
	switch strings.ToLower(s) {
	case CEST_STR_CA_MODE_ROOT:
		return CEST_CA_MODE_ROOT
	case CEST_STR_CA_MODE_SUBCA:
		return CEST_CA_MODE_SUBCA
	default:
		return CEST_CA_MODE_INVALID
	}
}

// Set the CA mode 
func SetCAMode(ca *CA, camode string) bool {
	var mode uint8

	if ca == nil {
		return false
	}

	mode = GetCAModeType(camode)
	if mode != CEST_CA_MODE_INVALID {
		ca.Mode = mode
		return true
	}

	return false
}

// Set the CA cert paths 
func SetCACertPath(ca *CA, cpath, kpath, chainpath string) bool {
	if ca == nil {
		return false
	}

	ca.Certpath = cpath
	ca.Keypath = kpath
	ca.Chainpath = chainpath

	return true
}

// Set CA CRL path 
func SetCACRLPath(ca *CA, crlpath string) bool {
	if ca == nil {
		return false
	}

	ca.Crlpath = crlpath

	return true
}

// Set CA validity 
func SetCAValidity(ca *CA, val uint64, unit string) bool {
	var valhours uint64

	if ca == nil {
		return false
	}

	valhours = GetValidityInHours(val, unit)
	if valhours == 0 {
		return false
	}

	ca.Validity = valhours

	return true
}

// Set CA Subjectname 
func SetCASubjectName(ca *CA, cn, o, c, ou string) bool {
	if ca == nil {
		return false
	}

	ca.Csr.Subname.Cn = cn
	ca.Csr.Subname.O = o
	ca.Csr.Subname.C = c
	ca.Csr.Subname.Ou = ou

	return true
}

// Set CA Sub Alt name 
func SetCASubjectAltName(ca *CA, ip, host string) bool {
	if ca == nil {
		return false
	}

	ca.Csr.Subaltname.Ip = ip
	ca.Csr.Subaltname.Host = host

	return true
}

// Set CA basic Attributes 
func SetCABasicAttr(ca *CA, maxpath uint8) bool {
	if ca == nil {
		return false
	}

	ca.Csr.Basicattr.Maxpathlen = maxpath

	return true
}

// Function to get keytype enum 
func GetKeyType(t string) uint8 {
	var x uint8
	switch strings.ToLower(t) {
	case CEST_STR_KEYTYPE_RSA:
		x = CEST_KEYTYPE_RSA
	case CEST_STR_KEYTYPE_ECDSA:
		x = CEST_KEYTYPE_ECDSA
	default:
		x = CEST_KEYTYPE_INVALID
	}
	return x
}

// Function to get the Signature Algo 
func GetSignatureType(t string) uint8 {
	var x uint8
	switch strings.ToLower(t) {
	case CEST_STR_SIGNATURE_ECDSA_SHA1:
		x = CEST_SIGNATURE_ECDSA_SHA1
	case CEST_STR_SIGNATURE_ECDSA_SHA256:
		x = CEST_SIGNATURE_ECDSA_SHA256
	case CEST_STR_SIGNATURE_ECDSA_SHA384:
		x = CEST_SIGNATURE_ECDSA_SHA384
	case CEST_STR_SIGNATURE_ECDSA_SHA512:
		x = CEST_SIGNATURE_ECDSA_SHA512
	default:
		x = CEST_SIGNATURE_INVALID
	}

	return x
}

// Set CA Key Info 
func SetCAKeyInfo(ca *CA, ktype string, klen uint16) bool {
	var x uint8

	if ca == nil {
		return false
	}

	x = GetKeyType(ktype)
	if x != CEST_KEYTYPE_INVALID {
		ca.Key.Ktype = x
		ca.Key.Length = klen
		return true
	}

	return false
}

// Set CA Signature Algorithm 
func SetCASignatureAlgoritm(ca *CA, algo string) bool {
	var x uint8

	if ca == nil {
		return false
	}

	x = GetSignatureType(algo)
	if x != CEST_SIGNATURE_INVALID {
		ca.Signature = x
		return true
	}

	return false
}

// Set Parent CA IP/Port 
func SetParentCAIP(ca *CA, ip string, port uint16) bool {
	if ca == nil {
		return false
	}

	ca.Parent.Addr.Ip = ip
	ca.Parent.Addr.Port = port

	return true
}

// Set Parent CA URL 
func SetParentCAURL(ca *CA, url string) bool {
	if ca == nil {
		return false
	}

	ca.Parent.Addr.Url = url

	return true
}

// Set Parent CA auth mode 
func SetParentCAAuthMode(ca *CA, mode string) bool {
	var x uint8

	if ca == nil {
		return false
	}
	x = GetESTAuthMethod(mode)
	if x != CEST_AUTH_METHOD_INVALID {
		ca.Parent.Authmode = x
		return true
	}

	return false
}

// Set Parent CA EST Params 
func SetEnrollParameter(ca *CA, fingerprint, uname, passwd string) bool {
	if ca == nil {
		return false
	}

	ca.Parent.Cafingerprint = fingerprint
	ca.Parent.Enrollid = uname
	ca.Parent.Passwd = passwd

	return true
}

// Set Parent CA TLS info 
func SetCATLSInfo(ca *CA, id, key, tstore string) bool {
	if ca == nil {
		return false
	}
	ca.Parent.Tls.Enabled = true
	ca.Parent.Tls.Idcertpath = id
	ca.Parent.Tls.Keypath = key
	ca.Parent.Tls.Tstorepath = tstore

	return true
}

// Debug Enabled ? 
func GetDebugFlag() bool {
	return GetGlobalConfig().debug
}

// Get Crypto Params 
func GetCryptoParams() *Crypto {
	return &(GetGlobalConfig().crypto)
}

// Get CRLSize 
func GetCRLSize() uint32 {
	return GetGlobalConfig().crlsize
}

// Get Admin Interface 
func GetAdminInterface() *AdminInterface {
	return &(GetGlobalConfig().admin)
}

// Get EST Interface 
func GetESTInterface() *ESTInterface {
	return &(GetGlobalConfig().est)
}

// Get DB 
func GetDBInfo() *DBInfo {
	return &(GetGlobalConfig().db)
}

// Get LDAP Info 
func GetLDAPInfo() *LDAPInfo {
	return &(GetGlobalConfig().ldap)
}

// Function to Print Config (rewrite later) 
func PrintConfigInfo() {
	var i uint32

	conf := GetGlobalConfig()
	fmt.Printf("\n#################EST CA CONFIG#####################")
	fmt.Printf("\ndebug      : %t", conf.debug)
	fmt.Printf("\nCRL Size   : %d", conf.crlsize)
	fmt.Printf("\nCrypto Information")
	fmt.Printf("\n    Encryption : %d", conf.crypto.Encryption)
	fmt.Printf("\n    Mode       : %d", conf.crypto.Mode)
	fmt.Printf("\n    Hash       : %d", conf.crypto.Hash)
	fmt.Printf("\n    Engine     : %d", conf.crypto.Engine)
	fmt.Printf("\nAdmin Interface")
	fmt.Printf("\n    IP   : %s", conf.admin.Addr.Ip)
	fmt.Printf("\n    Port : %d", conf.admin.Addr.Port)
	fmt.Printf("\nEST Interface")
	fmt.Printf("\n    IP          : %s", conf.est.Addr.Ip)
	fmt.Printf("\n    Port        : %d", conf.est.Addr.Port)
	fmt.Printf("\n    Auth method : %d", conf.est.Authmethod)
	fmt.Printf("\n    Idcert      : %s", conf.est.Tls.Idcertpath)
	fmt.Printf("\n    Key         : %s", conf.est.Tls.Keypath)
	fmt.Printf("\n    TrustStore  : %s", conf.est.Tls.Tstorepath)
	fmt.Printf("\nDB Info:")
	fmt.Printf("\n    DBType      : %d", conf.db.Dbtype)
	fmt.Printf("\n    DBFile      : %s", conf.db.Dbfile)
	fmt.Printf("\n    IP          : %s", conf.db.Addr.Ip)
	fmt.Printf("\n    Port        : %d", conf.db.Addr.Port)
	fmt.Printf("\n    URL         : %s", conf.db.Addr.Url)
	fmt.Printf("\n    Uname       : %s", conf.db.Uname)
	fmt.Printf("\n    Passwd      : %s", conf.db.Passwd)
	fmt.Printf("\n    Idcert      : %s", conf.db.Tls.Idcertpath)
	fmt.Printf("\n    Key         : %s", conf.db.Tls.Keypath)
	fmt.Printf("\n    TrustStore  : %s", conf.db.Tls.Tstorepath)
	fmt.Printf("\nLDAP Info:")
	fmt.Printf("\n    Enabled     : %t", conf.ldap.Enabled)
	fmt.Printf("\n    IP          : %s", conf.ldap.Addr.Ip)
	fmt.Printf("\n    Port        : %d", conf.ldap.Addr.Port)
	fmt.Printf("\n    URL         : %s", conf.ldap.Addr.Url)
	fmt.Printf("\n    Idcert      : %s", conf.ldap.Tls.Idcertpath)
	fmt.Printf("\n    Key         : %s", conf.ldap.Tls.Keypath)
	fmt.Printf("\n    TrustStore  : %s", conf.ldap.Tls.Tstorepath)
	fmt.Printf("\nCA Profiles:")
	var prof = conf.caprofiles.head
	for i = 0; i < conf.caprofiles.count; i++ {
		fmt.Printf("\n")
		fmt.Printf("\n  Profile: %s", prof.Name)
		fmt.Printf("\n     SubjectName   :")
		fmt.Printf("\n       CN = %s", prof.Attr.Subname.Cn)
		fmt.Printf("\n        C = %s", prof.Attr.Subname.C)
		fmt.Printf("\n        O = %s", prof.Attr.Subname.O)
		fmt.Printf("\n       OU = %s", prof.Attr.Subname.Ou)
		fmt.Printf("\n     SubjectAltName:")
		fmt.Printf("\n       IP   = %s", prof.Attr.Subaltname.Ip)
		fmt.Printf("\n       Host = %s", prof.Attr.Subaltname.Host)
		fmt.Printf("\n     Basic Attributes:")
		fmt.Printf("\n       ISCA     = %t", prof.Attr.Basicattr.Isca)
		fmt.Printf("\n       Max Path = %d", prof.Attr.Basicattr.Maxpathlen)
		fmt.Printf("\n     Validity      : %d hours", prof.Validity)
		prof = prof.next
	}
	fmt.Printf("\nCA List:")
	var ca = conf.calist.head
	for i = 0; i < conf.calist.count; i++ {
		fmt.Printf("\n")
		fmt.Printf("\n  CA: %s", ca.Name)
		fmt.Printf("\n     CA Mode       : %d", ca.Mode)
		fmt.Printf("\n     CertPath      : %s", ca.Certpath)
		fmt.Printf("\n     KeyPath       : %s", ca.Keypath)
		fmt.Printf("\n     ChainPath     : %s", ca.Chainpath)
		fmt.Printf("\n     CRLPath       : %s", ca.Crlpath)
		fmt.Printf("\n     SubjectName   :")
		fmt.Printf("\n       CN = %s", ca.Csr.Subname.Cn)
		fmt.Printf("\n        C = %s", ca.Csr.Subname.C)
		fmt.Printf("\n        O = %s", ca.Csr.Subname.O)
		fmt.Printf("\n       OU = %s", ca.Csr.Subname.Ou)
		fmt.Printf("\n     SubjectAltName:")
		fmt.Printf("\n       IP   = %s", ca.Csr.Subaltname.Ip)
		fmt.Printf("\n       Host = %s", ca.Csr.Subaltname.Host)
		fmt.Printf("\n     Basic Attributes:")
		fmt.Printf("\n       ISCA     = %t", ca.Csr.Basicattr.Isca)
		fmt.Printf("\n       Max Path = %d", ca.Csr.Basicattr.Maxpathlen)
		fmt.Printf("\n     Validity      : %d hours", ca.Validity)
		fmt.Printf("\n     KeyType       : %d", ca.Key.Ktype)
		fmt.Printf("\n     KeyLen        : %d", ca.Key.Length)
		fmt.Printf("\n     Signature Alg : %d", ca.Signature)
		fmt.Printf("\n     Parent CA:")
		fmt.Printf("\n       IP   = %s", ca.Parent.Addr.Ip)
		fmt.Printf("\n       Port = %d", ca.Parent.Addr.Port)
		fmt.Printf("\n       URL  = %s", ca.Parent.Addr.Url)
		fmt.Printf("\n       CAFP = %s", ca.Parent.Cafingerprint)
		fmt.Printf("\n       EID  = %s", ca.Parent.Enrollid)
		fmt.Printf("\n       PASS = %s", ca.Parent.Passwd)
		fmt.Printf("\n       Idcert      : %s", ca.Parent.Tls.Idcertpath)
		fmt.Printf("\n       Key         : %s", ca.Parent.Tls.Keypath)
		fmt.Printf("\n       TrustStore  : %s", ca.Parent.Tls.Tstorepath)
		ca = ca.next
	}
	fmt.Printf("\n")
}
