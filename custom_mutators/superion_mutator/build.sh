#!/bin/bash

cmake ./
make -j4 

cd js_parser

for f in *.cpp; do g++ -I ../runtime/src/ -I ~/Downloads/afl++ -c $f -fPIC -std=c++11 -fpermissive -Wattributes; done

g++  -shared -std=c++11 *.o ../dist/libantlr4-runtime.a  -o libTreeMutation.so 

cd ..
