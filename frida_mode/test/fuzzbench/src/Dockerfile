FROM gcr.io/fuzzbench/base-image

RUN apt-get update && \
    apt-get install -y wget libstdc++-5-dev libtool-bin automake flex bison \
                       libglib2.0-dev libpixman-1-dev python3-setuptools unzip \
                       git clang

# Download afl++
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git /afl && \
    cd /afl && git checkout dev

# Build afl++ without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.
RUN cd /afl && \
    unset CFLAGS && unset CXXFLAGS && \
    AFL_NO_X86=1 CC=clang PYTHON_INCLUDE=/ make && \
    make -C utils/aflpp_driver

# This makes interactive docker runs painless:
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV AFL_TESTCACHE_SIZE=2

RUN mkdir /frida-mode
WORKDIR /frida-mode
RUN cp /afl/afl-fuzz .
COPY build/assets/afl-frida-trace.so .
COPY build/assets/fuzz-target.dict .
COPY build/assets/fuzzer .

RUN mkdir /frida-mode/in
RUN split -l 1 -d -a 4 fuzz-target.dict /frida-mode/in/

WORKDIR /
COPY build/assets/run.sh .
RUN chmod +x /run.sh
