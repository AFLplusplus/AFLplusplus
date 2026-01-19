#!/usr/bin/env make
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Ricerca Security, Inc. All rights reserved.

SHELL:=bash
PREFIX?=$(shell pwd)/.local

CS_TRACE:=coresight-trace
LIBFORKSRV:=libforksrv.so

all: build

build:
	# git submodule update --init --recursive $(CS_TRACE)
	$(MAKE) -C $(CS_TRACE)
	cp $(CS_TRACE)/cs-proxy ../afl-cs-proxy
	cp $(CS_TRACE)/$(LIBFORKSRV) ../$(LIBFORKSRV)

debug:
	# git submodule update --init --recursive $(CS_TRACE)
	$(MAKE) -C $(CS_TRACE) DEBUG=1
	cp $(CS_TRACE)/cs-proxy ../afl-cs-proxy
	cp $(CS_TRACE)/$(LIBFORKSRV) ../$(LIBFORKSRV)

clean:
	$(MAKE) -C $(CS_TRACE) clean
	$(MAKE) -C $(CS_TRACE) dist-clean
	rm ../$(LIBFORKSRV) || true

.PHONY: all build debug clean
