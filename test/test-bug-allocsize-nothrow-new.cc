// ALLOCSIZE TP/TN: C++ nothrow new must be rewritten to the tracked malloc
// hook and the resulting binary must still run normally.
#include <cstddef>
#include <new>

int main(int argc, char **argv) {

  (void)argv;
  char *p = new (std::nothrow) char[(std::size_t)(argc + 16)];
  if (!p) return 1;
  p[0] = 1;
  delete[] p;
  return 0;

}
