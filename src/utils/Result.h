#pragma once

#include <variant>

#include "utils/Log.h"

// todo: merge Status into Result
template <typename T> struct OkType {
  T m_val;
  explicit OkType(T v) : m_val(std::move(v)) {}
};

template <typename E> struct ErrType {
  E m_val;
  explicit ErrType(E v) : m_val(std::move(v)) {}
};

template <typename T, typename E> class [[nodiscard]] Result {
  std::variant<T, E> m_storage;

public:
  Result(OkType<T> ok)
      : m_storage(std::in_place_index<0>, std::move(ok.m_val)) {}

  Result(ErrType<E> err)
      : m_storage(std::in_place_index<1>, std::move(err.m_val)) {}

  Result() = delete;

  bool IsOk() const noexcept { return m_storage.index() == 0; }

  bool IsErr() const noexcept { return m_storage.index() == 1; }

  T &Unwrap() {
    if (IsErr()) {
      LOGF("Attempted to unwrap an Err result");
    }
    return std::get<0>(m_storage);
  }

  const T &Unwrap() const {
    if (IsErr()) {
      LOGF("Attempted to unwrap an Err result");
    }
    return std::get<0>(m_storage);
  }

  T &Expect(const char *msg) {
    if (IsErr()) {
      throw std::runtime_error(msg);
    }
    return std::get<0>(m_storage);
  }

  T UnwrapOr(T default_val) const {
    if (IsOk()) {
      return std::get<0>(m_storage);
    }
    return default_val;
  }

  E &UnwrapErr() {
    if (IsOk()) {
      LOGF("Attempted to unwrap_err on an Ok result");
    }
    return std::get<1>(m_storage);
  }

  template <typename F> auto Map(F &&f) const {
    using U = std::invoke_result_t<F, const T &>;
    if (IsOk()) {
      return Result<U, E>(OkType<U>(f(std::get<0>(m_storage))));
    }
    return Result<U, E>(ErrType<E>(std::get<1>(m_storage)));
  }

  template <typename F> auto MapErr(F &&f) const {
    using NewE = std::invoke_result_t<F, const E &>;
    if (IsErr()) {
      return Result<T, NewE>(ErrType<NewE>(f(std::get<1>(m_storage))));
    }
    return Result<T, NewE>(OkType<T>(std::get<0>(m_storage)));
  }

  template <typename F> auto AndThen(F &&f) const {
    using NewResultType = std::invoke_result_t<F, const T &>;

    if (IsOk()) {
      return f(std::get<0>(m_storage));
    }
    return NewResultType(ErrType<E>(std::get<1>(m_storage)));
  }
};

// Helper functions for creating Result instances
template <typename T> constexpr OkType<T> Ok(T value) {
  return OkType<T>(std::move(value));
}

template <typename E> constexpr ErrType<E> Err(E error) {
  return ErrType<E>(std::move(error));
}