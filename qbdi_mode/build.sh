compiler_prefix="/home/hac425/workspace/android-standalone-toolchain-21-x86/bin/i686-linux-android-"
CFLAGS="-Iusr/local/include/ -Lusr/local/lib/"

# for x86-64 android
# compiler_prefix="/home/hac425/workspace/android-standalone-toolchain-21/bin/x86_64-linux-android-"
# CFLAGS="-Iandroid-x64/usr/local/include/ -Landroid-x64/usr/local/lib/"

${compiler_prefix}g++ -o loader template.cpp -lQBDI -ldl -w  -g ${CFLAGS}
${compiler_prefix}gcc -shared -o libdemo.so demo-so.c -w -g

cd ..
${compiler_prefix}gcc -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -I include/ -DAFL_PATH=\"/usr/local/lib/afl\" -DBIN_PATH=\"/usr/local/bin\" -DDOC_PATH=\"/usr/local/share/doc/afl\" -Wno-unused-function src/afl-fuzz-misc.c src/afl-fuzz-extras.c src/afl-fuzz-queue.c src/afl-fuzz-one.c src/afl-fuzz-python.c src/afl-fuzz-stats.c src/afl-fuzz-init.c src/afl-fuzz.c src/afl-fuzz-bitmap.c src/afl-fuzz-run.c src/afl-fuzz-globals.c src/afl-common.c src/afl-sharedmem.c src/afl-forkserver.c -o qbdi_mode/afl-fuzz  -ldl -w
