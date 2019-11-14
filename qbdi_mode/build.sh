if [ -z ${STANDALONE_TOOLCHAIN_PATH} ]; then
    echo "please set the android-standalone-toolchain path in STANDALONE_TOOLCHAIN_PATH environmental variable" 
    echo "for example: "
    echo "    export STANDALONE_TOOLCHAIN_PATH=/home/android-standalone-toolchain-21/" 
    exit
fi

if [ -z ${QBDI_SDK_PATH} ]; then
    echo "please set the qbdi sdk path in QBDI_SDK_PATH environmental variable" 
    echo "for example: "
    echo "    export QBDI_SDK_PATH=/home/QBDI-Android/" 
    exit
fi



if [ "$1" = "x86" ]; then
  echo "build x86 qbdi"
  compiler_prefix="${STANDALONE_TOOLCHAIN_PATH}/bin/i686-linux-android-"
elif [ "$1" = "x86_64" ]; then
    echo "build x86_64 qbdi"
    compiler_prefix="${STANDALONE_TOOLCHAIN_PATH}/bin/x86_64-linux-android-"
else
    echo "usage: ./build.sh arch[x86, x86_64]"
    exit
fi


CFLAGS="-I${QBDI_SDK_PATH}/usr/local/include/ -L${QBDI_SDK_PATH}/usr/local/lib/"

# build the qbdi template 
${compiler_prefix}g++ -o loader template.cpp -lQBDI -ldl -w  -g ${CFLAGS}

# build the demo share library
${compiler_prefix}gcc -shared -o libdemo.so demo-so.c -w -g

# build afl-fuzz
cd ..
${compiler_prefix}gcc -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -I include/ -DAFL_PATH=\"/usr/local/lib/afl\" -DBIN_PATH=\"/usr/local/bin\" -DDOC_PATH=\"/usr/local/share/doc/afl\" -Wno-unused-function src/afl-fuzz-misc.c src/afl-fuzz-extras.c src/afl-fuzz-queue.c src/afl-fuzz-one.c src/afl-fuzz-python.c src/afl-fuzz-stats.c src/afl-fuzz-init.c src/afl-fuzz.c src/afl-fuzz-bitmap.c src/afl-fuzz-run.c src/afl-fuzz-globals.c src/afl-common.c src/afl-sharedmem.c src/afl-forkserver.c -o qbdi_mode/afl-fuzz  -ldl -w
