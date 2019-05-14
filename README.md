## Overview

[Hyperledger Fabric](https://github.com/hyperledger/fabric) relies on X.509 Digital Certificates for identity management and PKI as a foundation for secure communication between blockchain nodes. However, the generation of the certificates requires administrator intervention either in the form of using "cryptogen" tool(for testing) or other proprietary methods of provisioning certificates to nodes.

An alternative standards based approach can be to use Enrollment over Secure Transport(EST) Certificate Authority. Hyperledger Fabric nodes can enroll themselves with the Org's CA either on bootup or on demand. Other features of EST such as CA rollover, automated certificate re-enrollment/renewal, enforcement of Proof of Possession(PoP) make it an attractive choice.

# Status

The EST-CA implementation is in alpha state.

# Prerequisites for building

EST-CA has a dependency on openssl-1.0.2g and libssl-dev-1.0.2g libraries(golang's TLS package does not support TLS/PSK). The required Go packages are gopkg.in/yaml.v1 and github.com/mattn/go-sqlite4.

# Building & Running

To build and run EST server -

/opt/gopath/src/$ export GOPATH=/opt/gopath/

/opt/gopath/src/$ git clone https://github.com/cisco/hyperledger-est-ca.git

/opt/gopath/src/github.com/cisco/hyperledger-est-ca$ ./build.sh

/opt/gopath/src/github.com/cisco/hyperledger-est-ca$ docker images
REPOSITORY        TAG          IMAGE ID        CREATED             SIZE
cisco/est-ca      0.0.3        8452043c0ba1    14 minutes ago      37.5MB

/opt/gopath/src/github.com/cisco/hyperledger-est-ca$ docker run -d --rm -e EST_CA_ADMIN_NAME="admin" -e EST_CA_ADMIN_PASSWD="Cisco@123" -p 443:443 -p 8080:8080 cisco/est-ca:0.0.3

EST Clients must use the APIs from caclient & chttp package.

# Testing

# Known limitations

* Compliance with [RFC 7030](https://tools.ietf.org/html/rfc7030)
* Support for Chunked CSR.
* See TODO file

# License

See LICENSE file.


