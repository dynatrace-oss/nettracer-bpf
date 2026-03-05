FROM ubuntu:18.04

ARG KERNEL_VERSION=4.15.0-101-generic
ARG BUILD_TYPE=Release
ARG LLVM_VERSION=16
ENV KERNEL_VERSION=$KERNEL_VERSION

RUN apt update -y && \
    apt-get install -y software-properties-common && \
	add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
	apt update -y && \
	apt install -y --fix-missing \
	wget lsb-release gpg  python3-pip git libelf-dev \
	make gcc-11 g++-11 linux-headers-$KERNEL_VERSION && \
	pip3 install --upgrade pip && \
	pip3 install conan==1.66.0 cmake==3.28.4
	# for the new clang
RUN  wget --timeout=10 --tries=3 -O - https://apt.llvm.org/llvm.sh | bash -s - $LLVM_VERSION && \
	update-alternatives --install /usr/bin/cc cc /usr/lib/llvm-16/bin/clang 800 && \
	update-alternatives --install /usr/bin/c++ c++ /usr/lib/llvm-16/bin/clang++ 800 && \
	conan config init && \
	conan profile update settings.compiler=clang default && \
	conan profile update settings.compiler.version=16        default && \
	conan profile update settings.compiler.libcxx=libstdc++11 default && \
	conan profile update  env.CC=/usr/lib/llvm-16/bin/clang  default && \
	conan profile update  env.C++=/usr/lib/llvm-16/bin/clang++  default && \
	conan profile show default

RUN mkdir /nettracer
WORKDIR /nettracer
COPY . .


RUN export PATH=$(dirname `find / -iname clang -type f`):$PATH && \
	cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -S . -B build  \
		-DCMAKE_INSTALL_PREFIX=./install  -DLLVM_VERSION=$LLVM_VERSION   \
		-DKERNEL_VERSION=$KERNEL_VERSION && \
	cmake --build build
