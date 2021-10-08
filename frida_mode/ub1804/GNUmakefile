PWD:=$(shell pwd)/
ROOT:=$(PWD)../../

.PHONY: all build docker clean shell test

all: docker
	docker run --rm \
		-v $(ROOT):/AFLplusplus \
		ub1804-afl-frida \
		/bin/sh -c \
			'make -C /AFLplusplus/ clean all && \
			make -C /AFLplusplus/frida_mode clean all'

test:
	docker run --rm \
		-v $(ROOT):/AFLplusplus \
		ub1804-afl-frida \
		/bin/sh -c \
			'make -C /AFLplusplus/frida_mode/test/png clean all && \
			make -C /AFLplusplus/frida_mode/test/png/persistent/hook frida'

build:
	docker run --rm \
		-v $(ROOT):/AFLplusplus \
		ub1804-afl-frida \
		/bin/sh -c \
			'make -C /AFLplusplus/ all && \
			make -C /AFLplusplus/frida_mode all'

docker:
	docker build --tag ub1804-afl-frida .

clean:
	docker images --filter 'dangling=true' -q --no-trunc | xargs -L1 docker rmi --force

shell:
	docker run -ti --rm ub1804-afl-frida /bin/bash
