#
# This Dockerfile for AFLplusplus uses Ubuntu 22.04 jammy and
# installs LLVM 14 for afl-clang-lto support :-)
#

FROM ubuntu:22.04 AS aflplusplus
LABEL "maintainer"="afl++ team <afl@aflplus.plus>"
LABEL "about"="AFLplusplus container image"

ARG DEBIAN_FRONTEND=noninteractive

ENV NO_ARCH_OPT=1
ENV IS_DOCKER=1

RUN apt-get update && apt-get full-upgrade -y && \
    apt-get install -y --no-install-recommends wget ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG LLVM_VERSION=14
ARG GCC_VERSION=12

RUN echo "deb [signed-by=/etc/apt/keyrings/llvm-snapshot.gpg.key] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-${LLVM_VERSION} main" > /etc/apt/sources.list.d/llvm.list && \
    wget -qO /etc/apt/keyrings/llvm-snapshot.gpg.key https://apt.llvm.org/llvm-snapshot.gpg.key

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
    make cmake automake meson ninja-build bison flex \
    git xz-utils bzip2 wget vim jupp nano bash-completion less \
    python3 python3-dev python3-setuptools python-is-python3 \
    libtool libtool-bin libglib2.0-dev \
    apt-utils apt-transport-https gnupg dialog \
    gnuplot-nox libpixman-1-dev \
    gcc-${GCC_VERSION} g++-${GCC_VERSION} gcc-${GCC_VERSION}-plugin-dev gdb lcov \
    clang-${LLVM_VERSION} clang-tools-${LLVM_VERSION} libc++1-${LLVM_VERSION} \
    libc++-${LLVM_VERSION}-dev libc++abi1-${LLVM_VERSION} libc++abi-${LLVM_VERSION}-dev \
    libclang1-${LLVM_VERSION} libclang-${LLVM_VERSION}-dev \
    libclang-common-${LLVM_VERSION}-dev libclang-cpp${LLVM_VERSION} \
    libclang-cpp${LLVM_VERSION}-dev liblld-${LLVM_VERSION} \
    liblld-${LLVM_VERSION}-dev liblldb-${LLVM_VERSION} liblldb-${LLVM_VERSION}-dev \
    libllvm${LLVM_VERSION} libomp-${LLVM_VERSION}-dev libomp5-${LLVM_VERSION} \
    lld-${LLVM_VERSION} lldb-${LLVM_VERSION} llvm-${LLVM_VERSION} \
    llvm-${LLVM_VERSION}-dev llvm-${LLVM_VERSION}-runtime llvm-${LLVM_VERSION}-tools \
    $([ "$(dpkg --print-architecture)" = "amd64" ] && echo gcc-${GCC_VERSION}-multilib gcc-multilib) \
    $([ "$(dpkg --print-architecture)" = "arm64" ] && echo libcapstone-dev) && \
    rm -rf /var/lib/apt/lists/*
    # gcc-multilib is only used for -m32 support on x86
    # libcapstone-dev is used for coresight_mode on arm64

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-${GCC_VERSION} 0 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-${GCC_VERSION} 0 && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${LLVM_VERSION} 0 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_VERSION} 0

RUN wget -qO- https://sh.rustup.rs | CARGO_HOME=/etc/cargo sh -s -- -y -q --no-modify-path
ENV PATH=$PATH:/etc/cargo/bin

ENV LLVM_CONFIG=llvm-config-${LLVM_VERSION}
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov && \
    (cd afl-cov && make install) && rm -rf afl-cov

# Until gcc v12.1 is released for ubuntu https://bugs.launchpad.net/ubuntu/+source/gcc-11/+bug/1940029
ARG NO_NYX=1

# Build currently broken
ARG NO_CORESIGHT=1
ARG NO_UNICORN_ARM64=1

WORKDIR /AFLplusplus
COPY . .

ARG CC=gcc-$GCC_VERSION
ARG CXX=g++-$GCC_VERSION

RUN sed -i 's/-$(MAKE)/$(MAKE)/g' GNUmakefile && make clean && \
    make distrib && make install && make clean

RUN echo "set encoding=utf-8" > /root/.vimrc && \
    echo ". /etc/bash_completion" >> ~/.bashrc && \
    echo 'alias joe="joe --wordwrap --joe_state -nobackup"' >> ~/.bashrc && \
    echo "export PS1='"'[afl++ \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc
