#!/usr/bin/env make
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Ricerca Security, Inc. All rights reserved.

SHELL:=bash
PREFIX?=$(shell pwd)/.local

CS_TRACE:=coresight-trace

PATCHELF?=$(PREFIX)/bin/patchelf

GLIBC_VER:=2.33
GLIBC_NAME:=glibc-$(GLIBC_VER)
GLIBC_URL_BASE:=http://ftp.gnu.org/gnu/glibc
GLIBC_PATCH:=patches/0002-glibc-Add-AFL-forkserver.patch
GLIBC_LDSO?=$(PREFIX)/lib/ld-linux-aarch64.so.1

OUTPUT?="$(TARGET).patched"

all: build

build:
	git submodule update --init --recursive $(CS_TRACE)
	$(MAKE) -C $(CS_TRACE)
	cp $(CS_TRACE)/cs-proxy ../afl-cs-proxy

patch: | $(PATCHELF) $(GLIBC_LDSO)
	@if test -z "$(TARGET)"; then echo "TARGET is not set"; exit 1; fi
	$(PATCHELF) \
	  --set-interpreter $(GLIBC_LDSO) \
	  --set-rpath $(dir $(GLIBC_LDSO)) \
	  --output $(OUTPUT) \
	  $(TARGET)

$(PATCHELF): patchelf
	git submodule update --init $<
	cd $< && \
	  ./bootstrap.sh && \
	  ./configure --prefix=$(PREFIX) && \
	  $(MAKE) && \
	  $(MAKE) check && \
	  $(MAKE) install

$(GLIBC_LDSO): | $(GLIBC_NAME).tar.xz
	tar -xf $(GLIBC_NAME).tar.xz
	patch -p1 < $(GLIBC_PATCH)
	mkdir -p $(GLIBC_NAME)/build
	cd $(GLIBC_NAME)/build && \
	  ../configure --prefix=$(PREFIX) && \
	  $(MAKE) && \
	  $(MAKE) install

$(GLIBC_NAME).tar.xz:
	wget -O $@ $(GLIBC_URL_BASE)/$@

clean:
	$(MAKE) -C $(CS_TRACE) clean

.PHONY: all build patch clean
