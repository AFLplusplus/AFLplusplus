#!/usr/bin/env bash
set -euo pipefail

echo "[*] Gramatron standalone AFL test runner"
echo "========================================"

ROOT_DIR="$(pwd)"
AFL_DIR="/src"
GRAMATRON_DIR="$ROOT_DIR"
AUTOMATON="$GRAMATRON_DIR/grammars/js/source_automata.json"

export AFL_NO_X86=1
export AFL_USE_ASAN=0
export AFL_CC_COMPILER=GCC

cat > target.c <<'EOF'
#include <unistd.h>
#include <stdint.h>

int main(void) {
  char buf[4096];
  read(0, buf, sizeof(buf));
  return 0;
}
EOF

echo "[+] target.c created"

echo "[*] Compiling target..."
gcc -O0 -g target.c -o target
chmod +x target

# Does uninstrumented binaries only

rm -rf input output
mkdir -p input output
echo "seed" > input/seed.js

echo "[*] Starting afl-fuzz with Gramatron..."

AFL_CUSTOM_MUTATOR_ONLY=1 \
AFL_CUSTOM_MUTATOR_LIBRARY=/src/custom_mutators/gramatron/gramatron.so \
GRAMATRON_AUTOMATION=/src/custom_mutators/gramatron/grammars/js/source_automata.json \
AFL_NO_FORKSRV=1 \
/src/afl-fuzz -n -i input -o output -- ./target

# Remove -n from here to make it work with instrumented binaries only