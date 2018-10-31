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

package cyaml

type Config struct {
	Debug        string
	Crlsizelimit int
	Crypto       crypto
	Admin        admin
	Est          est
	Db           db
	Ldap         ldap
	Caprofiles   caprofiles
	Ca           ca
}

type ca struct {
	Default string
	Ca_list []ca_list
}

type ca_list struct {
	Name                string
	Mode                string
	Cert_path           string
	Key_path            string
	Chain_path          string
	Crl_path            string
	Validity            validity
	Csr                 csr
	Key                 key
	Signature_algorithm string
	Parent_ca           parent_ca
}

type csr struct {
	Pathlength       int
	Subject_alt_name sub_alt_name
	Subject_name     attributes
}

type sub_alt_name struct {
	Ip   string `yaml:"IP"`
	Host string
}

type caprofiles struct {
	Default  string
	Profiles []profiles
}

type key struct {
	Length int
	Type   string
}

type parent_ca struct {
	Parenturl     string
	Authmode      string
	Cafingerprint string
	Enrollment_id string
	Password      string
	Tls           tls
}

type profiles struct {
	Name              string
	Validity          validity
	Attributes        attributes
	Basic_constraints basic_constraints
}

type validity struct {
	Period int
	Unit   string
}

type attributes struct {
	C  string `yaml:"C"`
	CN string `yaml:"CN"`
	O  string `yaml:"O"`
	OU string `yaml:"OU"`
	ST string `yaml:"ST"`
}

type basic_constraints struct {
	Is_ca         string `yaml:"is_ca"`
	Maxpathlength int
}

type crypto struct {
	Encryption string
	Mode       string
	Hash       string
	Type       string
}

type admin struct {
	Ip   string
	Port int
}

type est struct {
	Auth_method string
	Ip          string
	Port        int
	Tls         tls
}

type tls struct {
	Cert       string
	Key        string
	Truststore string
}

type db struct {
	Type       string
	Datastore  string
	Url        string
	Dbusername string
	Dbpassword string
	Tls        tls_db
}

type tls_db struct {
	Enabled    string
	Clientcert string
	Clientkey  string
	Servercert string
}

type ldap struct {
	Enabled string
	Url     string
	Tls     tls_ldap
}

type tls_ldap struct {
	Server_certs server_certs
	Client       client
}

type server_certs struct {
	Certfile string
}

type client struct {
	Certfile string
	Keyfile  string
}
