FROM fridadotre/manylinux-x86_64

RUN yum -y install xz

WORKDIR /AFLplusplus
ENV CFLAGS="\
    -DADDR_NO_RANDOMIZE=0x0040000 \
    -Wno-implicit-function-declaration \
    "
ENV CXX=$CC
