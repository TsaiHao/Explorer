#pragma once

#include <ostream>
#include <string>

enum class StatusCode : int8_t {
  kOk,
  kPermissionDenied,
  kNotFound,
  kBadArgument,
  kInvalidOperation,
  kInvalidState,
  kSdkFailure,
  kTimeout,
};

class Status {
public:
  Status();

  Status(StatusCode code, std::string_view message);
  ~Status();

  bool Ok() const;

  std::string_view Message() const;

  std::string_view CodeString() const;

private:
  // todo: optimize memory layout
  StatusCode m_code{StatusCode::kOk};
#ifdef EXP_DEBUG
  std::string m_message;
#endif
};

std::ostream &operator<<(std::ostream &os, const Status &status);

inline Status Ok() { return {}; }
inline Status PermissionDenied(std::string_view message) {
  return {StatusCode::kPermissionDenied, message};
}
inline Status NotFound(std::string_view message) {
  return {StatusCode::kNotFound, message};
}
inline Status BadArgument(std::string_view message) {
  return {StatusCode::kBadArgument, message};
}
inline Status InvalidOperation(std::string_view message) {
  return {StatusCode::kInvalidOperation, message};
}
inline Status InvalidState(std::string_view message) {
  return {StatusCode::kInvalidState, message};
}
inline Status SdkFailure(std::string_view message) {
  return {StatusCode::kSdkFailure, message};
}
inline Status Timeout(std::string_view message) {
  return {StatusCode::kTimeout, message};
}
