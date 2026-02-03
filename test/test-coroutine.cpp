#include <coroutine>

struct task {
  struct promise_type {
    std::suspend_always initial_suspend() {
      return {};
    }
    auto final_suspend() noexcept {
      struct awaiter {
        bool await_ready() noexcept {
          return false;
        }
        std::coroutine_handle<> await_suspend(
            std::coroutine_handle<>) noexcept {
          return std::noop_coroutine();
        }
        void await_resume() noexcept {
        }
      };
      return awaiter{};
    }
    task get_return_object() {
      return {};
    }
    void unhandled_exception() {
    }
    void return_void() {
    }
  };
};

task foo();
task foo() {
  co_return;
}
