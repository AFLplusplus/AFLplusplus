#!/bin/bash
# Test script to demonstrate the coverage map mismatch detection
# This creates two instrumented binaries where the second calls the first
# and verifies that the detection mechanism works correctly

set -e

TEST_DIR="/tmp/afl_coverage_test"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "[*] Setting up test environment..."

# Create a simple child binary (instrumented)
cat > child.c << 'EOF'
#include <stdio.h>

void child_func() {
    for (int i = 0; i < 1000; i++) {
        if (i % 2 == 0) {
            // This adds many edges to the coverage map
        }
    }
}

int main() {
    printf("Child binary executed\n");
    child_func();
    return 0;
}
EOF

# Create a parent binary that calls the child (also instrumented)
cat > parent.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void parent_func() {
    for (int i = 0; i < 500; i++) {
        if (i % 3 == 0) {
            // This adds edges to the coverage map
        }
    }
}

int main(int argc, char *argv[]) {
    printf("Parent binary started\n");
    parent_func();
    
    if (argc > 1 && argv[1][0] == 'c') {
        // Call child if argument provided
        printf("Calling child binary...\n");
        execv("./child", NULL);
        // If we reach here, exec failed
        perror("execv failed");
        return 1;
    }
    
    return 0;
}
EOF

# Create a test input file
echo "test input" > input.txt

echo "[*] Compiling with AFL++ instrumentation..."

# Compile both with AFL++ (this simulates the problematic scenario)
afl-cc -O2 -o child child.c 2>/dev/null || {
    echo "[!] Note: afl-cc not found. Please ensure AFL++ is installed and in PATH"
    echo "[!] Building with regular gcc instead (for demonstration)"
    gcc -O2 -o child child.c
}

afl-cc -O2 -o parent parent.c 2>/dev/null || {
    echo "[!] Falling back to regular gcc"
    gcc -O2 -o parent parent.c
}

echo "[*] Test setup complete"
echo ""
echo "To test the detection mechanism:"
echo ""
echo "1. Test default warning behavior:"
echo "   cd $TEST_DIR"
echo "   AFL_DUMP_MAP_SIZE=1 ./parent"
echo "   AFL_DUMP_MAP_SIZE=1 ./child"
echo ""
echo "2. When fuzzing with AFL++, the warning will appear if there's a mismatch:"
echo "   afl-fuzz -i . -o output ./parent c"
echo ""
echo "3. To make it crash on mismatch (for CI/CD):"
echo "   AFL_CRASH_ON_MAP_MISMATCH=1 ./parent c"
echo ""
echo "Clean up: rm -rf $TEST_DIR"
