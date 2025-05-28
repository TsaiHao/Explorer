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
  default:
    return "Unknown";
  }
}
} // namespace

Status::Status() = default;

Status::Status(StatusCode code, std::string_view message)
    : mCode(code), mMessage(message) {}

Status::~Status() = default;

bool Status::Ok() const { return mCode == StatusCode::kOk; }

std::string_view Status::Message() const {
#ifdef EXP_DEBUG
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-stack-address"
  // NOLINTBEGIN(bugprone-dangling-handle)
  return mMessage.empty() ? "No message" : mMessage;
  // NOLINTEND(bugprone-dangling-handle)
#pragma clang diagnostic pop
#else
  return "No message";
#endif
}

std::string_view Status::CodeString() const {
  return Ok() ? "OK" : GetCodeString(mCode);
}

std::ostream &operator<<(std::ostream &os, const Status &status) {
  return os << status.CodeString()
#ifdef EXP_DEBUG
            << "(" << status.Message() << ")";
#else
      ;
#endif
}