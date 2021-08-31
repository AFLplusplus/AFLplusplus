FROM fridadotre/manylinux-x86_64

COPY realpath /bin/realpath
RUN chmod +x /bin/realpath

RUN yum -y install xz
RUN yum -y install vim-common

WORKDIR /AFLplusplus
ENV CFLAGS="\
    -DADDR_NO_RANDOMIZE=0x0040000 \
    -Wno-implicit-function-declaration \
    "
ENV CXX=$CC
