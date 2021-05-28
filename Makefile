IMAGE_NAME=registry.lab.dynatrace.org/oneagent/oneagent-nettracer:latest
USER=$(shell id -u)
DEBUG?=0

ifeq ($(DEBUG), 1)
	BUILD_TYPE=Debug
else
	BUILD_TYPE=Release
endif

DOCKER_SUDO=$(shell docker version > /dev/null 2>&1 || echo "sudo")

all: build-image build-project-docker test-project-docker

build-image:
	$(DOCKER_SUDO) docker build --network=host \
		--build-arg BUILD_TYPE=$(BUILD_TYPE) \
		-t $(IMAGE_NAME) .

build-project-docker:
	$(DOCKER_SUDO) docker run --rm \
		-v $(shell pwd):/opt/mount:z \
		$(IMAGE_NAME) \
		cp -r /nettracer/build /opt/mount
	$(DOCKER_SUDO) chown -R 2000:2000 build

test-project-docker:
	$(DOCKER_SUDO) docker run --rm \
		-v $(shell pwd):/opt/mount:z \
		$(IMAGE_NAME) \
		bash -c 'cd build/libnettracer/test && ctest -T Test --no-compress-output --output-on-failure; \
			mkdir -p /opt/mount/build && cd /nettracer/build && cp ./**/test/Testing/**/Test.xml --parents /opt/mount/build'

dump-bpf-docker:
	$(DOCKER_SUDO) docker run --rm \
		-v $(shell pwd):/nettracer:z \
		--workdir=/nettracer \
		$(IMAGE_NAME) \
		bash -c 'export PATH="$$(dirname `find / -iname clang -type f`):$$PATH" && \
			mkdir -p build && \
			cd build && \
			cmake -DCMAKE_BUILD_TYPE=Debug \
				-DDEBUG_BPF=1
				-DKERNEL_VERSION=4.15.0-101-generic \
				-DGCC_VERSION=8 .. && \
			make bpf_program && \
			llvm-objdump -t -S -no-show-raw-insn bin/nettracer-bpf.o'

delete-image:
	$(DOCKER_SUDO) docker rmi -f $(IMAGE_NAME)

clean-docker: delete-image clean

build-project:
	mkdir -p build && \
	cd build && \
	cmake -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) .. && \
	make -j `nproc`

test-project:
	cd build/libnettracer/test && ctest -T Test --no-compress-output --output-on-failure

dump-bpf:
	mkdir -p build && \
	cd build && \
	cmake -DCMAKE_BUILD_TYPE=Debug \
		-DDEBUG_BPF=1 .. && \
	make bpf_program && \
	llvm-objdump -t -S -no-show-raw-insn bin/nettracer-bpf.o

clean:
	rm -rf build
