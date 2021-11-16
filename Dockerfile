FROM ubuntu:18.04

ARG KERNEL_VERSION=4.15.0-101-generic
ENV KERNEL_VERSION=$KERNEL_VERSION
RUN apt update -y && \
	apt install -y \
	# for the new clang
	wget lsb-release gpg software-properties-common \
	# for preparing dependencies
	git libelf-dev libboost-program-options-dev \
	make gcc-8 g++-8 linux-headers-$KERNEL_VERSION cmake && \
	# update links to use version 8.x of gcc/g++
	update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 800 --slave /usr/bin/g++ g++ /usr/bin/g++-8 && \
	update-alternatives --install /usr/bin/cc cc /usr/bin/gcc 100 --slave /usr/bin/c++ c++ /usr/bin/g++
RUN wget --timeout=10 --tries=3 -O - https://apt.llvm.org/llvm.sh | bash -s - 10

ARG FMT_VERSION=8.0.1
ENV FMT_VERSION=$FMT_VERSION
RUN git clone --depth 1 --branch $FMT_VERSION https://github.com/fmtlib/fmt.git && \
	cd fmt && mkdir build && cd build && \
	cmake -DFMT_TEST=OFF .. && make -j && make install
ARG SPDLOG_VERSION=1.9.2
ENV SPDLOG_VERSION=$SPDLOG_VERSION
RUN git clone --depth 1 --branch v$SPDLOG_VERSION https://github.com/gabime/spdlog.git && \
	cd spdlog && mkdir build && cd build && \
	cmake -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_FMT_EXTERNAL=ON .. && make -j && make install

WORKDIR /nettracer
COPY . .

ARG BUILD_TYPE=Release

RUN export PATH=$(dirname `find / -iname clang -type f`):$PATH && \
	mkdir -p build && \
	cd build && \
	cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE .. \
		-DCMAKE_INSTALL_PREFIX=./install \
		-DKERNEL_VERSION=$KERNEL_VERSION  &&\
	make -j `nproc`
