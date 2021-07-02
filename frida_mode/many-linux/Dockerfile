FROM fridadotre/manylinux-x86_64

COPY realpath /bin/realpath
RUN chmod +x /bin/realpath

RUN yum -y install xz
RUN yum -y install vim-common

WORKDIR /
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git

WORKDIR /AFLplusplus
RUN mkdir -p /AFLplusplus/frida_mode/build/frida/
RUN curl -L -o /AFLplusplus/frida_mode/build/frida/frida-gumjs-devkit-14.2.18-linux-x86_64.tar.xz "https://github.com/frida/frida/releases/download/14.2.18/frida-gumjs-devkit-14.2.18-linux-x86_64.tar.xz"

WORKDIR /AFLplusplus
RUN git checkout dev
WORKDIR /AFLplusplus/frida_mode
ENV CFLAGS="\
    -DADDR_NO_RANDOMIZE=0x0040000 \
    -Wno-implicit-function-declaration \
    "
ENV CXX=$CC
RUN make
