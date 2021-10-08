PWD:=$(shell pwd)/
ROOT:=$(PWD)../../
BUILD_DIR:=$(PWD)build/

.PHONY: all build docker clean shell

all: docker
	docker run --rm \
		-v $(ROOT):/AFLplusplus \
		many-afl-frida \
		make -C /AFLplusplus/frida_mode clean all

build:
	docker run --rm \
		-v $(ROOT):/AFLplusplus \
		many-afl-frida \
		make -C /AFLplusplus/frida_mode

docker:
	docker build --tag many-afl-frida .

clean:
	docker images --filter 'dangling=true' -q --no-trunc | xargs -L1 docker rmi --force

shell:
	docker run -ti --rm many-afl-frida /bin/bash
