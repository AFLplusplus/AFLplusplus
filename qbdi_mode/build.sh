# ~/workspace/android-standalone-toolchain-21-x86/bin/i686-linux-android-g++ -o loader  -Wl,-rpath,/data/lsl template.cpp -Iusr/local/include/ -Lusr/local/lib/ -lQBDI
# ~/workspace/android-standalone-toolchain-21-x86/bin/i686-linux-android-gcc -shared -o libdemo.so demo-so.c -w


g++ -o loader template.cpp -lQBDI -ldl -w
gcc -shared -o libdemo.so demo-so.c -w