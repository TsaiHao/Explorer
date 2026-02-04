//
// Created by Hao, Zaijun on 2025/4/29.
//

#include "Status.h"

namespace {
std::string_view GetCodeString(StatusCode code) {
  switch (code) {
  case StatusCode::kPermissionDenied:
    return "Permission Denied";
  case StatusCode::kNotFound:
    return "Not Found";
  case StatusCode::kBadArgument:
    return "Bad Argument";
  case StatusCode::kInvalidOperation:
    return "Invalid Operation";
  case StatusCode::kInvalidState:
    return "Invalid State";
  case StatusCode::kSdkFailure:
    return "Sdk failure";
  case StatusCode::kTimeout:
    return "Timeout";
  default:
    return "Unknown";
  }
}
} // namespace

Status::Status() = default;

Status::Status(StatusCode code, [[maybe_unused]] std::string_view message)
    : m_code(code)
#ifdef EXP_DEBUG
      ,
      m_message(message)
#endif
{
}

Status::~Status() = default;

bool Status::Ok() const { return m_code == StatusCode::kOk; }

std::string_view Status::Message() const {
#ifdef EXP_DEBUG
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-stack-address"
  // NOLINTBEGIN(bugprone-dangling-handle)
  return m_message.empty() ? "No message" : m_message;
  // NOLINTEND(bugprone-dangling-handle)
#pragma clang diagnostic pop
#else
  return "No message";
#endif
}

std::string_view Status::CodeString() const {
  return Ok() ? "OK" : GetCodeString(m_code);
}

std::string Status::DebugString() const {
#ifdef EXP_DEBUG
  return std::string(CodeString()) + " (" + std::string(Message()) + ")";
#else
  return std::string(CodeString());
#endif
}

StatusCode Status::Code() const { return m_code; }

std::ostream &operator<<(std::ostream &os, const Status &status) {
  return os << status.CodeString()
#ifdef EXP_DEBUG
            << "(" << status.Message() << ")";
#else
      ;
#endif
}