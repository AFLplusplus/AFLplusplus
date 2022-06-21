#
# This Dockerfile for AFLplusplus uses Ubuntu 22.04 jammy and
# installs LLVM 14 for afl-clang-lto support :-)
#

FROM ubuntu:22.04 AS aflplusplus
LABEL "maintainer"="afl++ team <afl@aflplus.plus>"
LABEL "about"="AFLplusplus docker image"

ARG DEBIAN_FRONTEND=noninteractive

ENV NO_ARCH_OPT 1

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
    make cmake automake \
    meson ninja-build bison flex \
    xz-utils \
    git \
    python3 python3-dev python3-setuptools python-is-python3 \
    libtool libtool-bin \
    libglib2.0-dev \
    wget vim jupp nano bash-completion less \
    apt-utils apt-transport-https ca-certificates gnupg dialog \
    libpixman-1-dev \
    gnuplot-nox && \
    rm -rf /var/lib/apt/lists/*

ARG LLVM_VERSION=14
ARG GCC_VERSION=12

RUN mkdir -p /usr/local/share/keyrings && \
    echo "deb [signed-by=/usr/local/share/keyrings/llvm-snapshot.gpg.key] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-${LLVM_VERSION} main" > /etc/apt/sources.list.d/llvm.list && \
    wget -qO /usr/local/share/keyrings/llvm-snapshot.gpg.key https://apt.llvm.org/llvm-snapshot.gpg.key

RUN apt-get update && apt-get full-upgrade -y && \
    apt-get -y install --no-install-recommends \
    gcc-${GCC_VERSION} g++-${GCC_VERSION} gcc-${GCC_VERSION}-plugin-dev gdb lcov \
    clang-${LLVM_VERSION} clang-tools-${LLVM_VERSION} libc++1-${LLVM_VERSION} libc++-${LLVM_VERSION}-dev \
    libc++abi1-${LLVM_VERSION} libc++abi-${LLVM_VERSION}-dev libclang1-${LLVM_VERSION} libclang-${LLVM_VERSION}-dev \
    libclang-common-${LLVM_VERSION}-dev libclang-cpp${LLVM_VERSION} libclang-cpp${LLVM_VERSION}-dev liblld-${LLVM_VERSION} \
    liblld-${LLVM_VERSION}-dev liblldb-${LLVM_VERSION} liblldb-${LLVM_VERSION}-dev libllvm${LLVM_VERSION} libomp-${LLVM_VERSION}-dev \
    libomp5-${LLVM_VERSION} lld-${LLVM_VERSION} lldb-${LLVM_VERSION} llvm-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev llvm-${LLVM_VERSION}-runtime llvm-${LLVM_VERSION}-tools && \
    rm -rf /var/lib/apt/lists/*

# arm64 doesn't have gcc-multilib, and it's only used for -m32 support on x86
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        apt-get update; \
        apt-get -y install --no-install-recommends \
        gcc-${GCC_VERSION}-multilib gcc-multilib; \
        rm -rf /var/lib/apt/lists/*; \
    fi
# RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-${LLVM_VERSION} 0 && \
#     update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-${LLVM_VERSION} 0

ENV LLVM_CONFIG=llvm-config-${LLVM_VERSION}
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov && \
    (cd afl-cov && make install) && rm -rf afl-cov

WORKDIR /AFLplusplus
COPY . .

RUN export CC=gcc-${GCC_VERSION} && export CXX=g++-${GCC_VERSION} && make clean && \
    make distrib && make install && make clean

RUN echo "set encoding=utf-8" > /root/.vimrc && \
    echo ". /etc/bash_completion" >> ~/.bashrc && \
    echo 'alias joe="joe --wordwrap --joe_state -nobackup"' >> ~/.bashrc && \
    echo "export PS1='"'[afl++ \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc
ENV IS_DOCKER="1"
