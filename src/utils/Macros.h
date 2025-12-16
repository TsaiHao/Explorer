#pragma once

#define DISABLE_COPY_AND_MOVE(C)                                               \
  C(const C &) = delete;                                                       \
  C &operator=(const C &) = delete;                                            \
  C(C &&) = delete;                                                            \
  C &&operator=(C &&) = delete;

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define EXPECT(x, y) __builtin_expect(x, (y))

#ifdef __cpp_lib_unreachable
#define UNREACHABLE() std::unreachable()
#elif defined(__clang__) || defined(__GNUC__)
#define UNREACHABLE() __builtin_unreachable()
#elif defined(_MSC_VER)
#define UNREACHABLE() __assume(false)
#else
#define UNREACHABLE()
#endif

#define THROW