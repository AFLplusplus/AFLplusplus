FROM ubuntu:eoan
MAINTAINER David Carlier <devnexen@gmail.com>
LABEL "about"="AFLplusplus docker image"
RUN apt-get update && apt-get install -y --no-install-recommends \
    automake \
    bison \
    build-essential \
    clang \
    clang-9 \
    flex \
    gcc-9 \
    gcc-9-plugin-dev \
    libc++-9-dev \
    libtool \
    libtool-bin \
    libglib2.0-dev \
    llvm-9-tools \
    python-setuptools \
    wget \
    && rm -fr /var/lib/apt/lists/*
RUN mkdir /app
WORKDIR ["/app"]
COPY . .
ENV CC=gcc-9
ENV CXX=g++-9
ENV LLVM_CONFIG=llvm-config-9
RUN make clean && make distrib && make install
