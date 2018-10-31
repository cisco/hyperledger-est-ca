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

package cca

import (
	"fmt"
	//"strings"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"est/cdb"
	"est/config"
	"math/big"
	"net"
	"strings"
	"time"
	//"github.com/cloudflare/cfssl/config"
	//cfcsr "github.com/cloudflare/cfssl/csr"
)

const (
	attrRoles          = "hf.Registrar.Roles"
	attrDelegateRoles  = "hf.Registrar.DelegateRoles"
	attrRevoker        = "hf.Revoker"
	attrIntermediateCA = "hf.IntermediateCA"
)

const (
	allRoles = "peer, orderer, client, auditor"
)

const (
	cahomedir = "ca"
)

type DN struct {
	issuer  string
	subject string
}

const (
	CurveP256 = 0
	CurveP384 = 1
	CurveP521 = 2
)

var CurveP256OID asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
var CurveP384OID asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
var CurveP521OID asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

var RoleName asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 29, 9}
var RoleLabel string = "roleName"

var oid = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "streetAddress",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.17":                   "postalCode",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generationQualifier",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.1":  "userid",
}

type CAServer struct {
	Name        string
	CAConfig    *config.CA
	EnrollCount uint64
	Cert        []byte
	Key         []byte
	LastSerial  []byte
}

var CAServerMap map[string]*CAServer

func GenerateECKey(curve uint8) (*ecdsa.PrivateKey, error) {
	var ecurve elliptic.Curve
	switch curve {
	case CurveP256:
		ecurve = elliptic.P256()
	case CurveP384:
		ecurve = elliptic.P384()
	case CurveP521:
		ecurve = elliptic.P521()
	default:
		return nil, nil
	}
	return ecdsa.GenerateKey(ecurve, rand.Reader)
}

func GenerateECCSR(csr *config.CertAttributes, key *ecdsa.PrivateKey, sigalgo uint) ([]byte, error) {
	random := rand.Reader
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         csr.Subname.Cn,
			OrganizationalUnit: []string{csr.Subname.Ou},
			Organization:       []string{csr.Subname.O},
			Country:            []string{csr.Subname.C},
		},
		SignatureAlgorithm: x509.SignatureAlgorithm(sigalgo),
		DNSNames:           []string{csr.Subaltname.Host},
		//IPAddresses:			[]net.IP{net.ParseIP(csr.Subaltname.Ip)},
	}
	if csr.Subaltname.Ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(csr.Subaltname.Ip)}
	}
	derBytes, err := x509.CreateCertificateRequest(random, &template, key)
	if err != nil {
		fmt.Printf("\nCould not generate CSR [%s]", err)
		return nil, err
	}

	return derBytes, err
}

func ParseCSR(csr []byte) (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(csr)
}

func ValidateCSR(csr *x509.CertificateRequest) bool {
	err := csr.CheckSignature()
	if err != nil {
		fmt.Printf("\nSignature validation for the CSR failed")
		return false
	}
	return true
}

func GetMaxValidity(startval, maxcaval time.Time, validity uint64) time.Duration {
	delta := maxcaval.Sub(startval)
	duration := time.Duration(validity) * time.Hour
	if duration >= delta {
		return delta
	}

	return duration
}

func UpdateCSRRole(csr *x509.CertificateRequest, enrollItem *cdb.EnrollTable) {
	var role pkix.Extension

	if enrollItem.Role == "" {
		return
	}
	value := RoleLabel + "=" + enrollItem.Role
	role.Id = RoleName
	role.Critical = false
	role.Value = []byte(value)

	csr.ExtraExtensions = []pkix.Extension{role}
}

func UpdateCSRSubName(csr *x509.CertificateRequest, enrollItem *cdb.EnrollTable,
	profItem *config.CAProfile) {
	/* Update CN to ID for now */
	csr.Subject.CommonName = enrollItem.EnrollId
	/* Profile takes precedence for attributes */
	if profItem.Attr.Subname.O != "" {
		csr.Subject.Organization = []string{profItem.Attr.Subname.O}
	}
	if profItem.Attr.Subname.Ou != "" {
		csr.Subject.OrganizationalUnit = []string{profItem.Attr.Subname.Ou}
	}
	if profItem.Attr.Subname.C != "" {
		csr.Subject.Country = []string{profItem.Attr.Subname.C}
	}
	/* The Sub Alt name should be cn.o */
	fqdn := strings.Join([]string{enrollItem.EnrollId, csr.Subject.Organization[0]}, ".")
	csr.DNSNames = []string{fqdn}
}

func GetCertObject(certder []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificates(certder)
	return cert[0], err
}

func GenerateSignedCert(csr *x509.CertificateRequest, cakey *ecdsa.PrivateKey,
	cacert *x509.Certificate, sigalgo uint,
	validity uint64, serial int64) ([]byte, error) {
	random := rand.Reader
	tnow := time.Now()
	duration := GetMaxValidity(tnow, cacert.NotAfter, validity)
	tfin := tnow.Add(duration)

	subkeyID, errkey := GetSubKeyIDFromPInterface(csr.PublicKey)
	if errkey != nil {
		fmt.Printf("\nCould not calculate Subject Key ID %s", errkey)
		return []byte(""), errkey
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               csr.Subject,
		NotBefore:             tnow,
		NotAfter:              tfin,
		SignatureAlgorithm:    x509.SignatureAlgorithm(sigalgo),
		SubjectKeyId:          subkeyID,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:            false,
		DNSNames:        csr.DNSNames,
		IPAddresses:     csr.IPAddresses,
		ExtraExtensions: csr.ExtraExtensions,
	}
	derBytes, err := x509.CreateCertificate(random, &template,
		cacert, csr.PublicKey, cakey)
	return derBytes, err
}

func GenerateSelfSignedCert(csr *config.CertAttributes, key *ecdsa.PrivateKey,
	sigalgo uint, validity uint64, serial int64) ([]byte, error) {
	random := rand.Reader
	duration := time.Duration(validity) * time.Hour
	tnow := time.Now()
	tfin := tnow.Add(duration)

	subkeyID, errkey := GetSubKeyID(key)
	if errkey != nil {
		fmt.Printf("\nCould not calculate Subject Key ID %s", errkey)
		return []byte(""), errkey
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:         csr.Subname.Cn,
			OrganizationalUnit: []string{csr.Subname.Ou},
			Organization:       []string{csr.Subname.O},
			Country:            []string{csr.Subname.C},
		},
		NotBefore:             tnow,
		NotAfter:              tfin,
		SignatureAlgorithm:    x509.SignatureAlgorithm(sigalgo),
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          subkeyID,
		BasicConstraintsValid: true,
		IsCA:        true,
		DNSNames:    []string{csr.Subaltname.Host},
		IPAddresses: []net.IP{net.ParseIP(csr.Subaltname.Ip)},
	}
	derBytes, err := x509.CreateCertificate(random, &template, &template, &key.PublicKey, key)
	return derBytes, err
}

func GetCertFingerprint(certder []byte) ([]byte, x509.SignatureAlgorithm) {
	res := make([]byte, 0, 0)
	ressigalgo := x509.SignatureAlgorithm(0)

	cert, err := x509.ParseCertificate(certder)
	if err != nil {
		fmt.Printf("\nCould not parse the certificate")
		return res, ressigalgo
	}

	return cert.Signature, cert.SignatureAlgorithm
}

func GetECKeyDer(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(key)
}

func GetECPubKeyDer(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&key.PublicKey)
}

func GetSHA1Hash(in []byte) []byte {
	hash := sha1.New()
	hash.Write(in)
	return hash.Sum(nil)
}

func GetSubKeyIDFromPInterface(pubkey interface{}) ([]byte, error) {
	pkeyDer, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		fmt.Printf("\nCould not get Pkey in DER [%s]", err)
		return []byte(""), err
	}
	return GetSHA1Hash(pkeyDer), nil
}

func GetSubKeyID(key *ecdsa.PrivateKey) ([]byte, error) {
	pkeyDer, err := GetECPubKeyDer(key)
	if err != nil {
		fmt.Printf("\nCould not Get Public Key In DER [%s]", err)
		return []byte(""), err
	}
	return GetSHA1Hash(pkeyDer), nil
}

func Base64Encode(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

func Base64Decode(in string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(in)
}

func GetECKeyPem(pk *ecdsa.PrivateKey) string {
	kder, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		fmt.Printf("\nGot Error [%s] while marshalling key", err)
		return ""
	}
	/* Encode the Pkey into PEM */
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	return string(keyPem)
}

func GetCertPem(cerder []byte) string {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cerder})
	return string(cert)
}

func GetECKeyPemWithAttr(pk *ecdsa.PrivateKey, curve uint8) string {
	var ecattrDer []byte
	var err1 error
	kder, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		fmt.Printf("\nGot Error [%s] while marshalling key", err)
		return ""
	}
	/* Get the EC Attributes */
	switch curve {
	case CurveP256:
		ecattrDer, err1 = asn1.Marshal(CurveP256OID)
	case CurveP384:
		ecattrDer, err1 = asn1.Marshal(CurveP384OID)
	case CurveP521:
		ecattrDer, err1 = asn1.Marshal(CurveP521OID)
	default:
		fmt.Printf("\nInvalid Curve")
		return ""
	}
	if err1 != nil {
		fmt.Printf("\nError while marshalling attribute [%s]", err1)
	}
	/* Encode EC Attributes into PEM */
	ecAttr := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: ecattrDer})
	/* Encode the Pkey into PEM */
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	pemOut := strings.Join([]string{string(ecAttr), string(keyPem)}, "\n")
	return pemOut
}

func PemEncode(in []byte, ptype string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: ptype, Bytes: in})
}

func PemDecode(in []byte) (*pem.Block, error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, errors.New("Error decoding PEM Block")
	}

	return block, nil
}

func HandleGetCACert(id string) ([]byte, error) {
	/* Connect To DB */
	db := cdb.InitDB(config.GetDBInfo().Dbfile)
	EnrollItem, count := cdb.SearchEnrollItem(db, id)
	if count != 1 {
		fmt.Printf("\nSomething wrong with Enroll Table")
		return nil, errors.New("Invalid Enroll ID")
	}
	if EnrollItem.Ca == "" {
		EnrollItem.Ca = config.GetDefaultCA()
	}
	ca, cacnt := cdb.SearchCaItem(db, EnrollItem.Ca)
	if cacnt != 1 {
		fmt.Printf("\nSomething is wrong with the DB for %s count %d", EnrollItem.Ca, cacnt)
		return nil, errors.New("DB Corrupt")
	}
	fmt.Printf("\nFound CAcert\n")
	cader, errd := Base64Decode(ca.Cert)
	return cader, errd
}

func HandleSimpleEnrollRequest(id, csr string) ([]byte, error) {
	var certItem cdb.CertTable

	/* Convert to Certificate Request Object */
	csrObj, err := ParseCSR([]byte(csr))
	if err != nil {
		fmt.Printf("\nInvalid CSR [%s]", err)
		return nil, err
	}
	/* Validate Signature */
	if !ValidateCSR(csrObj) {
		fmt.Printf("\nFailed to validate Signature on CSR")
		return nil, errors.New("Invalid CSR Signature")
	}
	/*
	 * Now that we have a valid CSR, lets first get the enrollment profile
	 * Check if a cert is already enrolled.. If yes, we will ignore this
	 * request. If not, we will update the CSR such that the CN is Enrol ID,
	 * SubAltName is id.SubAltName of Organisation. We will then create a new
	 * certficate, store it in the cert table. Set the Issued field as 1 in the
	 * enroll table and return the der cert enrolled
	 */

	/* First Get the Enroll Table Item */
	db := cdb.InitDB(config.GetDBInfo().Dbfile)
	EnrollItem, count := cdb.SearchEnrollItem(db, id)
	if count != 1 {
		fmt.Printf("\nSomething is wrong with the Enroll Table")
		return nil, errors.New("DB Corrupt")
	}
	/* Check if Cert already issued */
	if EnrollItem.Status != 0 {
		fmt.Printf("\nCert is Already issued for this ID.. Rejecting Request")
		return nil, errors.New("Cert Already Issued")
	}
	/* Set the CA name */
	if EnrollItem.Ca == "" {
		EnrollItem.Ca = config.GetDefaultCA()
	}
	/* Set the CA Profile Name */
	if EnrollItem.CaProfile == "" {
		EnrollItem.CaProfile = config.GetDefaultCAProfile()
	}
	/* lets get the CA Profile Item and CA item */
	ca, cacnt := cdb.SearchCaItem(db, EnrollItem.Ca)
	if cacnt != 1 {
		fmt.Printf("\nSomething is wrong with the DB")
		return nil, errors.New("DB Corrupt")
	}
	/* CA Profile will be stored in DB, however, currently, it is in Config */
	caProfile := config.FindCAProfileByName(EnrollItem.CaProfile)
	if caProfile == nil {
		fmt.Printf("\nDid not find a relevant CA Profile")
		return nil, errors.New("Invalid CA Profile")
	}
	/* Update the CSR to reflect the new CN/O/OU/C */
	UpdateCSRSubName(csrObj, &EnrollItem, caProfile)

	/* Update the CSR to reflect role */
	UpdateCSRRole(csrObj, &EnrollItem)

	/* Get Ca key obj */
	derk, errk := Base64Decode(ca.Key)
	if errk != nil {
		fmt.Printf("\nCould not get Ca Private Key [%s]", errk)
		return nil, errors.New("Failed to get Ca Key")
	}
	cakey, errK := x509.ParseECPrivateKey(derk)
	if errK != nil {
		fmt.Printf("\nCould not Decrypt Ca Key [%s]", errK)
		return nil, errors.New("Failed to decrypt CA Key")
	}
	/* Get CA Cert Obj */
	cacertder, errc := Base64Decode(ca.Cert)
	if errc != nil {
		fmt.Printf("\nError getting CA Cert [%s]", errc)
		return nil, errors.New("Failed to get Ca cert")
	}
	cacert, errC := GetCertObject(cacertder)
	if errC != nil {
		fmt.Printf("\nError parsing Ca cert [%s]", errC)
		return nil, errors.New("Failed to decode CA Cert")
	}
	/* Get Serial */
	serial := ca.Serial + 1
	/* Let us issue the certificate for this csr */
	ecert, errec := GenerateSignedCert(csrObj, cakey, cacert,
		uint(cacert.SignatureAlgorithm),
		caProfile.Validity, int64(serial))
	if errec != nil {
		fmt.Printf("\nCould not Generate EC Cert [%s]", errec)
		return nil, errec
	}
	/* Update the CA Serial */
	ca.Serial = ca.Serial + 1
	/* Update CA Enroll Count */
	ca.EnrollCount = ca.EnrollCount + 1
	/* Store the CA Item back into the DB */
	cdb.StoreCaItem(db, &ca)
	/* Update the EnrollItem */
	EnrollItem.Status = 1
	cdb.StoreEnrollItem(db, EnrollItem)
	/* create a Cert table entry */
	certItem.EnrollId = EnrollItem.EnrollId
	certItem.Certificate = Base64Encode(ecert)
	certItem.Csr = Base64Encode([]byte(csr))
	cdb.StoreCertItem(db, certItem)

	/* All done.. return the ecert now */
	return ecert, nil
}
