PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../..)/

.PHONY: all frida

all:
	make -C $(ROOT)frida_mode/

frida:
	LD_PRELOAD=$(ROOT)frida_mode/build/afl-frida-trace.so ./xml

debug:
	gdb --ex 'set environment LD_PRELOAD=$(ROOT)frida_mode/build/afl-frida-trace.so' --args ./xml