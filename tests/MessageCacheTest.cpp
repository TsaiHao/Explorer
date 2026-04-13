#include <gtest/gtest.h>

#include "utils/MessageCache.h"

#include <thread>
#include <vector>

using utils::MessageCache;

TEST(MessageCacheTest, PushAndDrain) {
  MessageCache cache;
  cache.Push(nlohmann::json{{"key", "value1"}});
  cache.Push(nlohmann::json{{"key", "value2"}});

  auto messages = cache.Drain();
  ASSERT_EQ(messages.size(), 2);
  EXPECT_EQ(messages[0]["key"], "value1");
  EXPECT_EQ(messages[1]["key"], "value2");
}

TEST(MessageCacheTest, DrainClearsCache) {
  MessageCache cache;
  cache.Push(nlohmann::json{{"a", 1}});

  auto first = cache.Drain();
  ASSERT_EQ(first.size(), 1);

  auto second = cache.Drain();
  EXPECT_TRUE(second.empty());
}

TEST(MessageCacheTest, DrainReportsDroppedCount) {
  MessageCache cache(2);
  cache.Push(nlohmann::json(1));
  cache.Push(nlohmann::json(2));
  cache.Push(nlohmann::json(3)); // drops 1

  size_t dropped = 0;
  auto messages = cache.Drain(dropped);
  ASSERT_EQ(messages.size(), 2);
  EXPECT_EQ(dropped, 1);
  EXPECT_EQ(messages[0], nlohmann::json(2));
  EXPECT_EQ(messages[1], nlohmann::json(3));
}

TEST(MessageCacheTest, DrainResetsDroppedCount) {
  MessageCache cache(1);
  cache.Push(nlohmann::json(1));
  cache.Push(nlohmann::json(2)); // drops 1
  cache.Push(nlohmann::json(3)); // drops 2

  size_t dropped = 0;
  cache.Drain(dropped);
  EXPECT_EQ(dropped, 2);

  // After drain, dropped count resets
  cache.Push(nlohmann::json(4));
  cache.Drain(dropped);
  EXPECT_EQ(dropped, 0);
}

TEST(MessageCacheTest, CapacityEnforced) {
  MessageCache cache(3);
  for (int i = 0; i < 10; ++i) {
    cache.Push(nlohmann::json(i));
  }

  EXPECT_EQ(cache.Size(), 3);
  EXPECT_EQ(cache.DroppedCount(), 7);

  auto messages = cache.Drain();
  ASSERT_EQ(messages.size(), 3);
  EXPECT_EQ(messages[0], nlohmann::json(7));
  EXPECT_EQ(messages[1], nlohmann::json(8));
  EXPECT_EQ(messages[2], nlohmann::json(9));
}

TEST(MessageCacheTest, EmptyDrain) {
  MessageCache cache;
  auto messages = cache.Drain();
  EXPECT_TRUE(messages.empty());
  EXPECT_EQ(cache.Size(), 0);
}

TEST(MessageCacheTest, ConcurrentPushAndDrain) {
  MessageCache cache(100);
  constexpr int kPushCount = 500;
  constexpr int kThreads = 4;

  auto push_fn = [&cache](int offset) {
    for (int i = 0; i < kPushCount; ++i) {
      cache.Push(nlohmann::json{offset * kPushCount + i});
    }
  };

  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back(push_fn, t);
  }

  // Drain concurrently while pushes are happening
  size_t total_drained = 0;
  for (int i = 0; i < 10; ++i) {
    auto msgs = cache.Drain();
    total_drained += msgs.size();
  }

  for (auto &t : threads) {
    t.join();
  }

  // Final drain
  auto remaining = cache.Drain();
  total_drained += remaining.size();

  // We pushed kThreads * kPushCount total, but capacity is 100 so many were dropped
  // Just verify no crash and total_drained <= total pushed
  EXPECT_LE(total_drained, kThreads * kPushCount);
}
