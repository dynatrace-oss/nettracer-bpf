IMAGE_NAME=registry.lab.dynatrace.org/oneagent/oneagent-nettracer:latest
CONTAINER_NAME=nettracer-build
USER=$(shell id -u)
DEBUG?=0

ifeq ($(DEBUG), 1)
	BUILD_TYPE=Debug
else
	BUILD_TYPE=Release
endif

DOCKER_SUDO=$(shell docker version > /dev/null 2>&1 || echo "sudo")

all: build-image build-project-docker test-project-docker

build-image : Dockerfile conanfile.txt
	$(DOCKER_SUDO) docker build --network=host \
		--build-arg BUILD_TYPE=$(BUILD_TYPE) \
		-t $(IMAGE_NAME) .
	touch build-image

build-project-docker:
	$(DOCKER_SUDO) docker run --rm \
		-v $(shell pwd):/opt/mount:z  --name $(CONTAINER_NAME) \
		$(IMAGE_NAME) bash -c "cp -r build /opt/mount && cd /opt/mount && cmake --build build"
	#$(DOCKER_SUDO) chown -R $(USER):$(USER) build

test-project-docker: build-project-docker
	$(DOCKER_SUDO) docker run --rm \
		-v $(shell pwd):/opt/mount:z  --name $(CONTAINER_NAME) \
		$(IMAGE_NAME) bash -c "cd /opt/mount/build && ctest"

delete-image:
	$(DOCKER_SUDO) docker rmi -f $(IMAGE_NAME)

clean:
	rm -rf build

full-clean: clean delete-image
