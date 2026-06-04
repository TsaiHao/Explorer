// Tests for http::ApiSchema request validation.
//
// Regression coverage for the 'pid' type check: nlohmann/json tags positive
// integer literals as number_unsigned (not number_integer), so a strict
// value_t comparison rejected valid PIDs like {"pid": 13450}.

#include "http/ApiSchema.h"
#include "utils/Status.h"

#include <gtest/gtest.h>

using http::ApiSchema;
using json = nlohmann::json;

namespace {

json StartData(const json &pid) {
  return json{{"pid", pid}, {"spawn", false}};
}

} // namespace

// --- The bug: a positive integer pid must be accepted ---

TEST(ApiSchemaTest, StartAcceptsUnsignedPid) {
  // nlohmann tags positive values as number_unsigned. A C++ int literal would
  // be tagged number_integer and miss the regression, so use an unsigned
  // literal to mirror how the value is actually stored.
  Status status = ApiSchema::ValidateStartRequest(StartData(13450u));
  EXPECT_TRUE(status.Ok()) << status.DebugString();
}

TEST(ApiSchemaTest, StartAcceptsPositiveIntegerPidViaParsedJson) {
  // The real regression path: an HTTP body is parsed, and the parser tags
  // positive integer literals as number_unsigned. This reproduced the bug.
  json request = json::parse(R"({"action":"start","data":{"pid":13450,"spawn":false}})");
  Status status = ApiSchema::ValidateRequest(request);
  EXPECT_TRUE(status.Ok()) << status.DebugString();
}

// --- Sibling checks that must still hold ---

TEST(ApiSchemaTest, StartRejectsZeroPid) {
  Status status = ApiSchema::ValidateStartRequest(StartData(0));
  EXPECT_FALSE(status.Ok());
  EXPECT_EQ(status.Code(), StatusCode::kBadArgument);
}

TEST(ApiSchemaTest, StartRejectsNegativePid) {
  // A negative integer is tagged number_integer and passes the type check,
  // but must be rejected by the positivity check.
  Status status = ApiSchema::ValidateStartRequest(StartData(-13450));
  EXPECT_FALSE(status.Ok());
  EXPECT_EQ(status.Code(), StatusCode::kBadArgument);
}

TEST(ApiSchemaTest, StartRejectsNonIntegerPid) {
  // A string pid is still a genuine type error.
  Status status = ApiSchema::ValidateStartRequest(StartData("13450"));
  EXPECT_FALSE(status.Ok());
  EXPECT_EQ(status.Code(), StatusCode::kBadArgument);
}

TEST(ApiSchemaTest, StartRejectsFloatPid) {
  Status status = ApiSchema::ValidateStartRequest(StartData(13450.5));
  EXPECT_FALSE(status.Ok());
  EXPECT_EQ(status.Code(), StatusCode::kBadArgument);
}
