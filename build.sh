#!/bin/sh
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

set -e
set -x

export dockerfile="Dockerfile"
export tag="0.0.3"

NS=cisco

echo Building $NS/est-ca:$tag

docker build --build-arg https_proxy=$https_proxy \
    --build-arg http_proxy=$http_proxy \
    -t $NS/est-ca:$tag . -f $dockerfile --no-cache
