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
}

Status::Status() = default;

Status::Status(StatusCode code, std::string_view message) : mCode(code) {
  (void)message;
}

Status::~Status() = default;

bool Status::Ok() const { return mCode == StatusCode::kOk; }

std::string_view Status::Message() const {
  // todo: implement
  return "";
}

std::string_view Status::CodeString() const {
  return Ok() ? "OK" : GetCodeString(mCode);
}

std::ostream &operator<<(std::ostream &os, const Status &status) {
  return os << status.CodeString();
}