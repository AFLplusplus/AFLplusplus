FROM gcc:8.3.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    automake \
    bison \
    clang \
    flex \
    gcc-8-plugin-dev \
    libc++-7-dev \
    libtool \
    libtool-bin \
    llvm-7-tools \
    python-setuptools \
    && rm -fr /var/lib/apt/lists/*
RUN mkdir /app
WORKDIR ["/app"]
COPY . .
ENV CC=gcc-8
ENV CXX=g++-8
ENV LLVM_CONFIG=llvm-config-7
RUN make clean && make distrib && make tests
