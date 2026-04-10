//
// Created by Hao, Zaijun on 2025/4/27.
//
#pragma once

#ifdef EXPLORER_USE_COROUTINES

#include <coroutine>
#include <optional>
#include <utility>

#include "FridaHelper.h"
#include "utils/Result.h"
#include "utils/Status.h"

namespace frida {

// ---------------------------------------------------------------------------
// Task<T> — Lazy coroutine return type with symmetric transfer
// ---------------------------------------------------------------------------

template <typename T = void> class Task;

namespace detail {

struct TaskPromiseBase {
  std::coroutine_handle<> m_continuation{std::noop_coroutine()};

  auto initial_suspend() noexcept { return std::suspend_always{}; }

  struct FinalAwaiter {
    bool await_ready() noexcept { return false; }

    template <typename Promise>
    std::coroutine_handle<>
    await_suspend(std::coroutine_handle<Promise> h) noexcept {
      return h.promise().m_continuation;
    }

    void await_resume() noexcept {}
  };

  auto final_suspend() noexcept { return FinalAwaiter{}; }

  void unhandled_exception() { m_exception = std::current_exception(); }

  std::exception_ptr m_exception{nullptr};
};

template <typename T> struct TaskPromise : TaskPromiseBase {
  std::optional<T> m_value;

  Task<T> get_return_object();

  void return_value(T value) { m_value.emplace(std::move(value)); }

  T &result() {
    if (m_exception) {
      std::rethrow_exception(m_exception);
    }
    return *m_value;
  }
};

template <> struct TaskPromise<void> : TaskPromiseBase {
  Task<void> get_return_object();

  void return_void() {}

  void result() {
    if (m_exception) {
      std::rethrow_exception(m_exception);
    }
  }
};

} // namespace detail

template <typename T> class Task {
public:
  using promise_type = detail::TaskPromise<T>;
  using handle_type = std::coroutine_handle<promise_type>;

  explicit Task(handle_type h) : m_handle(h) {}

  Task(Task &&other) noexcept : m_handle(std::exchange(other.m_handle, {})) {}

  Task &operator=(Task &&other) noexcept {
    if (this != &other) {
      if (m_handle) {
        m_handle.destroy();
      }
      m_handle = std::exchange(other.m_handle, {});
    }
    return *this;
  }

  Task(const Task &) = delete;
  Task &operator=(const Task &) = delete;

  ~Task() {
    if (m_handle) {
      m_handle.destroy();
    }
  }

  // Awaitable interface
  bool await_ready() const noexcept { return false; }

  std::coroutine_handle<>
  await_suspend(std::coroutine_handle<> continuation) noexcept {
    m_handle.promise().m_continuation = continuation;
    return m_handle; // symmetric transfer
  }

  decltype(auto) await_resume() { return m_handle.promise().result(); }

  // Start the coroutine and block until completion (for sync callers).
  // Only valid when the Task is a top-level coroutine (no continuation).
  decltype(auto) StartSync() {
    m_handle.resume();
    return m_handle.promise().result();
  }

private:
  handle_type m_handle;
};

namespace detail {

template <typename T> Task<T> TaskPromise<T>::get_return_object() {
  return Task<T>{std::coroutine_handle<TaskPromise<T>>::from_promise(*this)};
}

inline Task<void> TaskPromise<void>::get_return_object() {
  return Task<void>{
      std::coroutine_handle<TaskPromise<void>>::from_promise(*this)};
}

} // namespace detail

// ---------------------------------------------------------------------------
// GLibAwaitable — Bridges GLib async/finish pattern to co_await
// ---------------------------------------------------------------------------

namespace detail {

// Storage passed through GAsyncReadyCallback user_data
struct AsyncCallbackData {
  std::coroutine_handle<> handle;
  GAsyncResult *result{nullptr};
};

// Trampoline invoked by GLib on Frida's internal main loop thread
inline void AsyncReadyTrampoline(GObject * /*source*/, GAsyncResult *res,
                                 gpointer user_data) {
  auto *data = static_cast<AsyncCallbackData *>(user_data);
  data->result = static_cast<GAsyncResult *>(g_object_ref(res));
  data->handle.resume();
}

} // namespace detail

// ---------------------------------------------------------------------------
// frida_async() — Awaitable wrapper for Frida GLib async APIs
//
// For async functions returning a value via _finish:
//   auto result = co_await frida_async<ReturnType>(
//       frida_device_attach,          // async fn
//       frida_device_attach_finish,   // finish fn
//       device, pid, options          // args before cancellable
//   );
//
// For async functions with void _finish:
//   co_await frida_async(
//       frida_session_detach,         // async fn
//       frida_session_detach_finish,  // finish fn
//       session                       // args before cancellable
//   );
// ---------------------------------------------------------------------------

// Detect whether a finish function returns void or a value
template <typename FinishFn, typename Self>
using FinishReturnType =
    decltype(std::declval<FinishFn>()(std::declval<Self *>(),
                                      std::declval<GAsyncResult *>(),
                                      std::declval<GError **>()));

// Non-void finish: returns Result<T, Status>
template <typename ReturnT, typename AsyncFn, typename FinishFn, typename Self,
          typename... Args>
struct GLibAwaitable {
  AsyncFn m_async_fn;
  FinishFn m_finish_fn;
  Self *m_self;
  std::tuple<Args...> m_args;
  GCancellable *m_cancellable;
  detail::AsyncCallbackData m_cb_data{};

  bool await_ready() noexcept { return false; }

  void await_suspend(std::coroutine_handle<> h) {
    m_cb_data.handle = h;
    std::apply(
        [&](auto &...args) {
          m_async_fn(m_self, args..., m_cancellable,
                     detail::AsyncReadyTrampoline, &m_cb_data);
        },
        m_args);
  }

  Result<ReturnT, Status> await_resume() {
    GError *error = nullptr;
    ReturnT value = m_finish_fn(m_self, m_cb_data.result, &error);
    g_object_unref(m_cb_data.result);

    if (error != nullptr) {
      auto status = SdkFailure(error->message);
      g_error_free(error);
      return Err(std::move(status));
    }
    return Ok(std::move(value));
  }
};

// Void finish: returns Status
template <typename AsyncFn, typename FinishFn, typename Self, typename... Args>
struct GLibAwaitableVoid {
  AsyncFn m_async_fn;
  FinishFn m_finish_fn;
  Self *m_self;
  std::tuple<Args...> m_args;
  GCancellable *m_cancellable;
  detail::AsyncCallbackData m_cb_data{};

  bool await_ready() noexcept { return false; }

  void await_suspend(std::coroutine_handle<> h) {
    m_cb_data.handle = h;
    std::apply(
        [&](auto &...args) {
          m_async_fn(m_self, args..., m_cancellable,
                     detail::AsyncReadyTrampoline, &m_cb_data);
        },
        m_args);
  }

  Status await_resume() {
    GError *error = nullptr;
    m_finish_fn(m_self, m_cb_data.result, &error);
    g_object_unref(m_cb_data.result);

    if (error != nullptr) {
      auto status = SdkFailure(error->message);
      g_error_free(error);
      return status;
    }
    return Ok();
  }
};

// Factory: non-void finish → Result<T, Status>
template <typename ReturnT, typename AsyncFn, typename FinishFn, typename Self,
          typename... Args>
auto frida_async(AsyncFn async_fn, FinishFn finish_fn, Self *self,
                 Args... args) {
  return GLibAwaitable<ReturnT, AsyncFn, FinishFn, Self, Args...>{
      async_fn, finish_fn, self, std::tuple<Args...>{std::move(args)...},
      nullptr};
}

// Factory: void finish → Status
template <typename AsyncFn, typename FinishFn, typename Self, typename... Args>
  requires std::is_void_v<FinishReturnType<FinishFn, Self>>
auto frida_async(AsyncFn async_fn, FinishFn finish_fn, Self *self,
                 Args... args) {
  return GLibAwaitableVoid<AsyncFn, FinishFn, Self, Args...>{
      async_fn, finish_fn, self, std::tuple<Args...>{std::move(args)...},
      nullptr};
}

} // namespace frida

#endif // EXPLORER_USE_COROUTINES
