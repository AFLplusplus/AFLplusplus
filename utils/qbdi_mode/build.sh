
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
  compiler_prefix="${STANDALONE_TOOLCHAIN_PATH}/bin/"
  if [ -z ${CC} ]; then
      export CC=i686-linux-android-gcc
  fi
  if [ -z ${CXX} ]; then
      export CXX=i686-linux-android-g++
  fi
elif [ "$1" = "x86_64" ]; then
    echo "build x86_64 qbdi"
    compiler_prefix="${STANDALONE_TOOLCHAIN_PATH}/bin/"
    if [ -z ${CC} ]; then
        export CC=x86_64-linux-android-gcc
    fi
    if [ -z ${CXX} ]; then
        export CXX=x86_64-linux-android-g++
    fi
else
    echo "usage: ./build.sh arch[x86, x86_64]"
    exit
fi


CFLAGS="-I${QBDI_SDK_PATH}/usr/local/include/ -L${QBDI_SDK_PATH}/usr/local/lib/"

echo "[+] Building the QBDI template"
# build the qbdi template 
${compiler_prefix}${CXX} -o loader template.cpp -lQBDI -ldl -w  -g ${CFLAGS}

echo "[+] Building the demo library"
# build the demo share library
${compiler_prefix}${CC} -shared -o libdemo.so demo-so.c -w -g

echo "[+] Building afl-fuzz for Android"
# build afl-fuzz
cd ../..
${compiler_prefix}${CC} -DANDROID_DISABLE_FANCY=1 -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -I include/ -DAFL_PATH=\"/usr/local/lib/afl\" -DBIN_PATH=\"/usr/local/bin\" -DDOC_PATH=\"/usr/local/share/doc/afl\" -Wno-unused-function src/afl-fuzz*.c src/afl-common.c src/afl-sharedmem.c src/afl-forkserver.c src/afl-performance.c -o utils/qbdi_mode/afl-fuzz -ldl -lm -w

echo "[+] All done. Enjoy!"
