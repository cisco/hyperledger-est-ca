# Copyright (c) 2019 Cisco and/or its affiliates.
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

FROM golang:1.12.5 as build

RUN apt-get -y update && \
  apt-get -y install libssl1.0-dev 

WORKDIR /go/src/github.com/cisco/hyperledger-est-ca

COPY vendor  vendor

COPY cca     cca
COPY chttp   chttp
COPY client  client
COPY config  config
COPY cssl    cssl
COPY cyaml   cyaml
COPY cdb     cdb
COPY est_server_main.go .
COPY Makefile .

RUN make all

FROM alpine:3.9

RUN addgroup -S app \
    && adduser -S -g app app

WORKDIR /app

EXPOSE 8080
EXPOSE 443

COPY --from=build /go/src/github.com/cisco/hyperledger-est-ca/bin/est_server .
COPY --from=build /go/src/github.com/cisco/hyperledger-est-ca/config/config.yaml .

RUN chown -R app:app ./

USER app

ENTRYPOINT ["/app/est_server"]
CMD ["config.yaml"]
