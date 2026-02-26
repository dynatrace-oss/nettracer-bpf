# Copyright 2023 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:18.04
ARG KERNEL_VERSION=4.15.0-101-generic
ENV KERNEL_VERSION=$KERNEL_VERSION

RUN apt-get update -y && \
    # for add-apt-repository
    apt-get install -y software-properties-common && \
    # needed for updated libstdc++-9-dev containing filesystem namespace
    add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt-get install -y wget lsb-release gpg libelf-dev libstdc++-9-dev python3-pip git linux-headers-$KERNEL_VERSION bash && \
    # install clang 17
    wget --timeout=10 --tries=3 -O - https://apt.llvm.org/llvm.sh | bash -s - 17 && \
    # update links to clang as default compiler
    update-alternatives --install /usr/bin/cc cc /usr/lib/llvm-17/bin/clang 800 && \
    update-alternatives --install /usr/bin/c++ c++ /usr/lib/llvm-17/bin/clang++ 800 && \
    pip3 install --upgrade pip && \
	pip3 install conan==1.66.0 cmake==3.26.1

ENV PATH="/usr/lib/llvm-17/bin:$PATH"
