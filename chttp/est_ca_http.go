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

package chttp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"est/cca"
	"est/cdb"
	"est/config"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

type Ca struct {
	Caname string `json:"caname"`
}

type RevokeCert struct {
	EnrollId string `json:"enrollId"`
	SerialNo int64  `json:"serialNo"`
	OcspCode string `json:"ocspcode"`
}

type FingerprintRes struct {
	Fingerprint string `json:"Fingerprint"`
	FpAlgo      int    `json:"FpAlgo"`
}

type EnrollResponse struct {
	Success string `json:"Success"`
	Message string `json:"Message"`
}

type CreateEnrolProf struct {
	EnrollId     string `json:"enrollId"`
	EnrollSecret string `json:"enrollSecret"`
	CaProfile    string `json:"caProfile"`
	CaName       string `json:"caName"`
	Role         string `json:"role"`
	/*	Cn           string `json:"cn"`
		Ou           string `json:"ou"`
		C            string `json:"c"`
		O            string `json:"o"`  */
}

type ClosingBuffer struct {
	*bytes.Buffer
}

func (cb *ClosingBuffer) Close() error {
	return nil
}

func CreateHTTPResponse(statuscode int, req *http.Request, ctype, body string) []byte {
	var resp http.Response
	var rc io.ReadCloser

	fmt.Printf("\nCreating HTTP response with body len: %d", len(body))

	resp.Status = http.StatusText(statuscode)
	resp.StatusCode = statuscode
	resp.Proto = req.Proto
	resp.ProtoMajor = req.ProtoMajor
	resp.ProtoMinor = req.ProtoMinor
	resp.Header = make(map[string][]string)
	resp.Header["Content-Type"] = []string{ctype}
	resp.Header["Connection"] = []string{"Close"}
	resp.ContentLength = int64(len(body))
	resp.Close = req.Close

	cb := &ClosingBuffer{bytes.NewBufferString(body)}
	rc = cb
	resp.Body = rc
	rc.Close()

	buffer := new(bytes.Buffer)
	resp.Write(buffer)

	newString := buffer.String()
	fmt.Printf("\nResponse is %s", newString)
	return []byte(newString)

}

func HandleInvalidRequest(r *http.Request) []byte {
	resp := CreateHTTPResponse(http.StatusBadRequest, r, "", "")
	return resp
}

func GetSuccessJson() string {
	return "{ \"Success\":\"Success\",\n\"Message\":\"OK\"\n }"
}

func GetFailureJson(reason string) string {
	var buff bytes.Buffer
	prepends := "{ \"Success\":\"Failure\",\n\"Message\":\""
	appends := "\"\n}"

	buff.WriteString(prepends)
	buff.WriteString(reason)
	buff.WriteString(appends)
	return buff.String()
}

func HttpHandleESTRequest(data []byte, id string) []byte {
	readbuffer := bytes.NewBuffer(data)
	reader := bufio.NewReader(readbuffer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Printf("\nError %s while processing request", err)
		return []byte("")
	}

	resp := []byte("")
	switch reqPath := req.URL.Path; reqPath {
	case "/simpleenroll":
		fmt.Printf("\nEST Simple Enroll Request")
		resp = SimpleEnrollReqHandler(req, id)
	case "/getcacert":
		fmt.Printf("\nEST Get CA Cert Request")
		resp = GetCACertReqHandler(req, id)
	default:
		fmt.Println("Invalid Request Found %s", reqPath)
		resp = HandleInvalidRequest(req)
	}
	return resp
}

func HttpHandleAdminRequest(data []byte) []byte {
	readbuffer := bytes.NewBuffer(data)
	reader := bufio.NewReader(readbuffer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Printf("\nError %s while processing request", err)
		return []byte("")
	}
	resp := []byte("")
	switch reqPath := req.URL.Path; reqPath {
	case "/getfingerprint":
		resp = GetFingerprintReqHandler(req)
	case "/revokecertificate":
		fmt.Printf("\nReceived RevokeCert Request.. Not Supported")
		resp = HandleInvalidRequest(req)
	case "/createenrollprofile":
		fmt.Println("Create Enrollment Profile")
		resp = CreateEnrolmentProfReqHandler(req)
	default:
		fmt.Println("Invalid AdminRequest Found %s", reqPath)
		resp = HandleInvalidRequest(req)
	}

	return resp
}

func SimpleEnrollReqHandler(req *http.Request, id string) []byte {
	/* validate the header */
	if req.Method != http.MethodPost {
		fmt.Printf("\nInvalid Request Type for Simple Enroll")
		return HandleInvalidRequest(req)
	}
	/* validate content type */
	if req.Header.Get("Content-Type") != "application/pkcs10" {
		fmt.Printf("\nInvalid Content Type %s", req.Header.Get("Content-Type"))
		return HandleInvalidRequest(req)
	}
	body, _ := ioutil.ReadAll(req.Body)
	ecert, err := cca.HandleSimpleEnrollRequest(id, string(body))
	if err != nil {
		fmt.Printf("\nError issuing Certificate [%s]", err)
		return HandleInvalidRequest(req)
	}
	return CreateHTTPResponse(200, req, "application/pkcs10", string(ecert))
}

func GetCACertReqHandler(req *http.Request, id string) []byte {
	/* validate the header */
	if req.Method != http.MethodGet {
		fmt.Printf("\nInvalid Request Type for Simple Enroll")
		return HandleInvalidRequest(req)
	}

	cacert, err := cca.HandleGetCACert(id)
	if err != nil {
		fmt.Printf("\nError getting CA cert [%s]", err)
		return HandleInvalidRequest(req)
	}
	return CreateHTTPResponse(200, req, "application/pkcs10", string(cacert))
}

func GetFingerprintReqHandler(r *http.Request) []byte {
	var ca Ca

	if r.Method != http.MethodPost {
		fmt.Printf("\nInvalid Request Type for Simple Enroll")
		return HandleInvalidRequest(r)
	}

	body, _ := ioutil.ReadAll(r.Body)
	fingerprintRes := FingerprintRes{}
	err := json.Unmarshal(body, &ca)
	if err != nil {
		fmt.Printf("\nCould not unmarshal the JSON request")
		return HandleInvalidRequest(r)
	}

	/* If CA Name is nil then get default CA */
	if ca.Caname == "" {
		ca.Caname = config.GetDefaultCA()
	}

	/* database retrieval workflow */
	db := cdb.InitDB(config.GetDBInfo().Dbfile)
	item, count := cdb.SearchCaItem(db, ca.Caname)
	if count == 0 {
		return CreateHTTPResponse(200, r, "application/json", GetFailureJson("Invalid Name"))
	}
	fingerprintRes.Fingerprint = item.Fingerprint
	fingerprintRes.FpAlgo = item.FpAlgo
	fingerprintResJson, err := json.Marshal(fingerprintRes)
	if err != nil {
		return CreateHTTPResponse(200, r, "application/json", GetFailureJson("Sys failure"))
	}
	resp := CreateHTTPResponse(200, r, "application/json", string(fingerprintResJson))
	return resp
}

/* TODO: This api is not being used yet.. will be supported */
func RevokeCertificateReqHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	var revokeCert RevokeCert
	err := json.Unmarshal(body, &revokeCert)
	if err != nil {
		fmt.Printf("\nInvalid JSON")
	}
	fmt.Println(revokeCert.SerialNo)
	io.WriteString(w, "success")
}

func CreateEnrolmentProfReqHandler(r *http.Request) []byte {
	var createEnrolProf CreateEnrolProf
	if r.Method != http.MethodPost {
		fmt.Printf("\nInvalid Request Type for Simple Enroll")
		return HandleInvalidRequest(r)
	}
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &createEnrolProf)

	if err != nil {
		fmt.Printf("\nCould not get the Body for the Enrollment Request")
		return HandleInvalidRequest(r)
	}
	db := cdb.InitDB(config.GetDBInfo().Dbfile)
	item := cdb.EnrollTable{createEnrolProf.EnrollId,
		createEnrolProf.EnrollSecret, "", 0,
		createEnrolProf.Role, createEnrolProf.CaName, createEnrolProf.CaProfile}
	_, count := cdb.SearchEnrollItem(db, createEnrolProf.EnrollId)
	if count != 0 {
		return CreateHTTPResponse(200, r, "application/json", GetFailureJson("Profile Already Exists"))
	}
	cdb.StoreEnrollItem(db, item)
	resp := CreateHTTPResponse(200, r, "application/json", GetSuccessJson())
	return resp
}

/*
 * HTTP Client APIs
 */
func byteRequest(req http.Request) []byte {

	buf := new(bytes.Buffer)
	err := req.Write(buf)
	if err != nil {
		fmt.Printf("\nError while converting to buff %s", err)
		return nil
	}
	newStr := buf.String()
	fmt.Printf(newStr)
	return []byte(newStr)
}

func GetFingerprintRequest(caname string) []byte {

	url := fmt.Sprintf("http://" + "127.0.0.1" + "/getfingerprint")
	prep := "{\"caname\":\""
	post := "\"\n}"
	jsonReq := strings.Join([]string{prep, caname, post}, "")
	payload := strings.NewReader(jsonReq)
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("content-type", "application/json")
	sendByte := byteRequest(*req)

	return sendByte
}

func GetCreateEnrolProfRequest(eid, esec, caprof, caname, role string) []byte {
	url := fmt.Sprintf("http://" + "127.0.0.1" + "/createenrollprofile")
	jsonReq := fmt.Sprintf("{\"enrollId\":\"" + eid +
		"\",\n\"enrollSecret\":\"" + esec +
		"\",\n\"caProfile\":\"" + caprof +
		"\",\n\"role\":\"" + role +
		"\",\n\"caName\":\"" + caname + "\"\n}")

	payload := strings.NewReader(jsonReq)
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("Cache-control", "no-cache")
	req.Header.Add("Content-type", "application/json")
	sendByte := byteRequest(*req)
	return sendByte
}

func GetSimpleEnrollRequest(payload string) []byte {
	url := fmt.Sprintf("http://" + "127.0.0.1" + "/simpleenroll")
	body := strings.NewReader(payload)
	req, _ := http.NewRequest("POST", url, body)
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Content-Type", "application/pkcs10")
	sendByte := byteRequest(*req)
	return sendByte
}

func GetGetCACertRequest() []byte {
	url := fmt.Sprintf("http://" + "127.0.0.1" + "/getcacert")
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Content-Type", "application/pkcs10")
	sendByte := byteRequest(*req)
	return sendByte
}

func HandleGetFingerprintResponse(res []byte) (int, []byte, error) {
	var resjson FingerprintRes
	readbuffer := bytes.NewBuffer(res)
	reader := bufio.NewReader(readbuffer)
	resp, _ := http.ReadResponse(reader, nil)
	body, _ := ioutil.ReadAll(resp.Body)

	/* Check if 200 OK? */
	if resp.StatusCode != 200 {
		fmt.Printf("\nFailure Response %s", resp.Status)
		return 0, nil, errors.New(resp.Status)
	}
	err := json.Unmarshal(body, &resjson)
	if err != nil {
		fmt.Printf("\nGet Fingerprint failed")
		fmt.Printf("\n%s", body)
		return 0, nil, errors.New("Negative response")
	}
	return resjson.FpAlgo, []byte(resjson.Fingerprint), nil

}

func HandleCreateEnrolProfResponse(res []byte) bool {
	var resjson EnrollResponse
	readbuffer := bytes.NewBuffer(res)
	reader := bufio.NewReader(readbuffer)
	resp, _ := http.ReadResponse(reader, nil)
	body, _ := ioutil.ReadAll(resp.Body)
	/* Check if 200 OK? */
	if resp.StatusCode != 200 {
		fmt.Printf("\nFailure Response %s", resp.Status)
		return false
	}
	err := json.Unmarshal(body, &resjson)
	if err != nil {
		fmt.Printf("\nInvalid Response")
		return false
	}
	if resjson.Success == "Success" {
		fmt.Printf("\n Create Enrollment Profile Successful")
	}
	return true
}

func HandleSimpleEnrollResponse(res []byte) (string, error) {
	readbuffer := bytes.NewBuffer(res)
	reader := bufio.NewReader(readbuffer)
	resp, _ := http.ReadResponse(reader, nil)
	body, _ := ioutil.ReadAll(resp.Body)
	/* Check if 200 OK? */
	if resp.StatusCode != 200 {
		fmt.Printf("\nFailure Response %s", resp.Status)
		return "", errors.New(resp.Status)
	}

	if resp.Header.Get("Content-Type") != "application/pkcs10" {
		fmt.Printf("\nInvalid Content Type")
		return "", errors.New("\nInvalid Content Type")
	}

	/* It was successful, so we have the body.. lets pem encode and return */
	return cca.GetCertPem([]byte(body)), nil
}

func HandleGetCACertResponse(res []byte) (string, error) {
	readbuffer := bytes.NewBuffer(res)
	reader := bufio.NewReader(readbuffer)
	resp, _ := http.ReadResponse(reader, nil)
	body, _ := ioutil.ReadAll(resp.Body)
	/* Check if 200 OK? */
	if resp.StatusCode != 200 {
		fmt.Printf("\nFailure Response %s", resp.Status)
		return "", errors.New(resp.Status)
	}
	if resp.Header.Get("Content-Type") != "application/pkcs10" {
		fmt.Printf("\nInvalid Content Type")
		return "", errors.New("\nInvalid Content Type")
	}

	/* It was successful, so we have the body.. lets pem encode and return */
	return cca.GetCertPem([]byte(body)), nil
}
