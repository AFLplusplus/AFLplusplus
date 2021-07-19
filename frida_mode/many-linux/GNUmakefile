PWD:=$(shell pwd)/
BUILD_DIR:=$(PWD)build/

.PHONY: all clean shell

all: | $(BUILD_DIR)
	docker build --tag many-afl-frida .
	docker run --rm \
		-v $(PWD)build/:/export \
		many-afl-frida \
		cp /AFLplusplus/afl-frida-trace.so /export

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
	docker images --filter 'dangling=true' -q --no-trunc | xargs -L1 docker rmi --force

shell:
	docker run -ti --rm many-afl-frida /bin/bash
