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

SERVER_OUT := "bin/est_server"
PKG := "github.com/cisco/hyperledger-est-ca"
SERVER_PKG_BUILD := "${PKG}"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

.PHONY: all

all: server

dep: ## Get the dependencies
	@go get -v -d ./...

server: dep ## Build est server
	@CGO_ENABLED=1 GOOS=linux go build -i -v -ldflags "-extldflags -static" -o $(SERVER_OUT) $(SERVER_PKG_BUILD)

clean: ## Remove previous builds
	@rm $(SERVER_OUT)

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
