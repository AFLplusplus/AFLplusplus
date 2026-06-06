/*
   C++20 coroutine + AFL_LLVM_PATH must not produce a use-after-free in
   the destroy path. The shared PathAnalysis hoists a stack alloca
   (path_reg) and inserts loads/stores at exits — across coroutine
   suspend points those spill into the coroutine frame, and the destroy
   path reloads after the frame is freed. PATH must skip any function
   containing coroutine intrinsics.

   This test verifies the SKIP (no DEBUG: PATH function=co_func line),
   not the UAF itself.
*/

#include <coroutine>
#include <unistd.h>

struct Task {

  struct promise_type {

    Task get_return_object() { return Task{}; }
    std::suspend_never initial_suspend() noexcept { return {}; }
    std::suspend_never final_suspend() noexcept { return {}; }
    void return_void() {}
    void unhandled_exception() {}

  };

};

__attribute__((noinline)) Task co_func(unsigned char x) {

  if (x & 1) co_return;
  co_await std::suspend_never{};
  co_return;

}

__attribute__((noinline)) int normal_func(unsigned char x) {

  if (x & 1) return 1;
  if (x & 2) return 2;
  return 0;

}

int main(int argc, char **argv) {

  unsigned char buf[1] = {0};
  if (read(0, buf, 1) <= 0) return 2;
  co_func(buf[0]);
  return normal_func(buf[0]);

}
