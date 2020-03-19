FROM ubuntu:eoan
MAINTAINER David Carlier <devnexen@gmail.com>
LABEL "about"="AFLplusplus docker image"
RUN apt-get update && apt-get -y install \
    --no-install-suggests --no-install-recommends \
    automake \
    bison \
    build-essential \
    clang \
    clang-9 \
    flex \
    git \
    python3.7 \
    python3.7-dev \
    gcc-9 \
    gcc-9-plugin-dev \
    gcc-9-multilib \
    libc++-9-dev \
    libtool \
    libtool-bin \
    libglib2.0-dev \
    llvm-9-dev \
    python-setuptools \
    python2.7-dev \
    wget \
    ca-certificates \
    libpixman-1-dev \
    && rm -rf /var/lib/apt/lists/*

ARG CC=gcc-9
ARG CXX=g++-9
ARG LLVM_CONFIG=llvm-config-9

RUN git clone https://github.com/AFLplusplus/AFLplusplus

RUN cd AFLplusplus && make clean && make distrib && \
    make install && cd .. && rm -rf AFLplusplus
