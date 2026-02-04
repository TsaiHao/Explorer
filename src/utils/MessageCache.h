//
// Created by Hao, Zaijun on 2025/2/6.
//
#pragma once

#include "nlohmann/json.hpp"

#include <cstddef>
#include <deque>
#include <mutex>
#include <vector>

namespace utils {

/**
 * Thread-safe bounded message cache.
 * Stores JSON messages in a FIFO queue with a configurable capacity.
 * When capacity is exceeded, oldest messages are dropped.
 */
class MessageCache {
public:
  static constexpr size_t kDefaultCapacity = 1000;

  explicit MessageCache(size_t capacity = kDefaultCapacity)
      : m_capacity(capacity) {}

  /**
   * Push a message into the cache.
   * If the cache is at capacity, the oldest message is dropped.
   * @param msg The JSON message to cache
   */
  void Push(nlohmann::json msg) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_buffer.size() >= m_capacity) {
      m_buffer.pop_front();
      ++m_dropped_count;
    }
    m_buffer.push_back(std::move(msg));
  }

  /**
   * Atomically drain all messages from the cache.
   * @return Vector of all cached messages; cache is empty after this call
   */
  std::vector<nlohmann::json> Drain() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<nlohmann::json> result(
        std::make_move_iterator(m_buffer.begin()),
        std::make_move_iterator(m_buffer.end()));
    m_buffer.clear();
    m_dropped_count = 0;
    return result;
  }

  /**
   * Atomically drain all messages and return dropped count.
   * @param dropped_count Output: number of messages dropped since last drain
   * @return Vector of all cached messages
   */
  std::vector<nlohmann::json> Drain(size_t &dropped_count) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<nlohmann::json> result(
        std::make_move_iterator(m_buffer.begin()),
        std::make_move_iterator(m_buffer.end()));
    m_buffer.clear();
    dropped_count = m_dropped_count;
    m_dropped_count = 0;
    return result;
  }

  /**
   * Get current number of cached messages.
   */
  size_t Size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_buffer.size();
  }

  /**
   * Get number of messages dropped since last drain due to overflow.
   */
  size_t DroppedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_dropped_count;
  }

private:
  mutable std::mutex m_mutex;
  std::deque<nlohmann::json> m_buffer;
  size_t m_capacity;
  size_t m_dropped_count{0};
};

} // namespace utils
