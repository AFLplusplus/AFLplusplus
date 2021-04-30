#!/bin/bash
AFL_QEMU_DRIVER_NO_HOOK=1 \
AFL_FRIDA_PERSISTENT_CNT=1000000 \
AFL_FRIDA_PERSISTENT_ADDR=0x55555599f6c0 \
/frida-mode/afl-fuzz \
	-O \
	-i /frida-mode/in \
	-o /frida-mode/out \
	-- \
		/frida-mode/fuzzer