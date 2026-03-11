FROM ubuntu:18.04

ARG KERNEL_VERSION=4.15.0-101-generic
ARG BUILD_TYPE=Release
ARG LLVM_VERSION=17
ENV KERNEL_VERSION=${KERNEL_VERSION}
ENV LLVM_VERSION=${LLVM_VERSION}
ENV BUILD_TYPE=${BUILD_TYPE}
ENV PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"

RUN apt-get update -y && \
	apt-get install -y --no-install-recommends software-properties-common ca-certificates && \
	add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
	apt-get update -y && \
	apt-get install -y --fix-missing --no-install-recommends \
		wget lsb-release gpg python3-pip git libelf-dev bash \
		linux-headers-${KERNEL_VERSION} \
		make gcc-11 g++-11 libstdc++-9-dev && \
	wget --timeout=10 --tries=3 -O - https://apt.llvm.org/llvm.sh | bash -s - "${LLVM_VERSION}" && \
	update-alternatives --install /usr/bin/cc cc "/usr/lib/llvm-${LLVM_VERSION}/bin/clang" 800 && \
	update-alternatives --install /usr/bin/c++ c++ "/usr/lib/llvm-${LLVM_VERSION}/bin/clang++" 800 && \
	python3 -m pip install --upgrade pip setuptools wheel && \
	pip3 install conan==1.66.0 cmake==3.28.4 && \
	rm -rf /var/lib/apt/lists/*
