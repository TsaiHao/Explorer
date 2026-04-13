#include <gtest/gtest.h>

#include "utils/Result.h"
#include "utils/Status.h"

#include <string>

TEST(ResultTest, OkValue) {
  Result<int, Status> r = Ok(42);
  EXPECT_TRUE(r.IsOk());
  EXPECT_FALSE(r.IsErr());
  EXPECT_EQ(r.Unwrap(), 42);
}

TEST(ResultTest, ErrValue) {
  Result<int, Status> r = Err(NotFound("missing"));
  EXPECT_FALSE(r.IsOk());
  EXPECT_TRUE(r.IsErr());
  EXPECT_EQ(r.UnwrapErr().Code(), StatusCode::kNotFound);
}

TEST(ResultTest, UnwrapOr) {
  Result<int, Status> ok = Ok(10);
  Result<int, Status> err = Err(BadArgument("bad"));

  EXPECT_EQ(ok.UnwrapOr(99), 10);
  EXPECT_EQ(err.UnwrapOr(99), 99);
}

TEST(ResultTest, Map) {
  Result<int, Status> r = Ok(5);
  auto mapped = r.Map([](const int &v) { return v * 2; });

  EXPECT_TRUE(mapped.IsOk());
  EXPECT_EQ(mapped.Unwrap(), 10);
}

TEST(ResultTest, MapOnErr) {
  Result<int, Status> r = Err(SdkFailure("fail"));
  auto mapped = r.Map([](const int &v) { return v * 2; });

  EXPECT_TRUE(mapped.IsErr());
  EXPECT_EQ(mapped.UnwrapErr().Code(), StatusCode::kSdkFailure);
}

TEST(ResultTest, MapErr) {
  Result<int, Status> r = Err(NotFound("x"));
  auto mapped = r.MapErr([](const Status &s) { return s.Code(); });

  EXPECT_TRUE(mapped.IsErr());
  EXPECT_EQ(mapped.UnwrapErr(), StatusCode::kNotFound);
}

TEST(ResultTest, AndThen) {
  Result<int, Status> r = Ok(10);
  auto chained = r.AndThen([](const int &v) -> Result<std::string, Status> {
    return Ok<std::string>(std::to_string(v));
  });

  EXPECT_TRUE(chained.IsOk());
  EXPECT_EQ(chained.Unwrap(), "10");
}

TEST(ResultTest, AndThenOnErr) {
  Result<int, Status> r = Err(Timeout("slow"));
  auto chained = r.AndThen([](const int &v) -> Result<std::string, Status> {
    return Ok<std::string>(std::to_string(v));
  });

  EXPECT_TRUE(chained.IsErr());
  EXPECT_EQ(chained.UnwrapErr().Code(), StatusCode::kTimeout);
}

TEST(StatusTest, OkStatus) {
  Status s = Ok();
  EXPECT_TRUE(s.Ok());
  EXPECT_EQ(s.Code(), StatusCode::kOk);
}

TEST(StatusTest, ErrorStatuses) {
  EXPECT_EQ(PermissionDenied("x").Code(), StatusCode::kPermissionDenied);
  EXPECT_EQ(NotFound("x").Code(), StatusCode::kNotFound);
  EXPECT_EQ(BadArgument("x").Code(), StatusCode::kBadArgument);
  EXPECT_EQ(InvalidOperation("x").Code(), StatusCode::kInvalidOperation);
  EXPECT_EQ(InvalidState("x").Code(), StatusCode::kInvalidState);
  EXPECT_EQ(SdkFailure("x").Code(), StatusCode::kSdkFailure);
  EXPECT_EQ(Timeout("x").Code(), StatusCode::kTimeout);
}
