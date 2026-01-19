#pragma once

#include <algorithm>
#include <functional>
#include <iterator>
#include <utility>
#include <vector>

#include "utils/Macros.h"

template <typename KeyType, typename ValueType> class SmallMap {
  using PairType = std::pair<KeyType, ValueType>;
  using StorageContainer = std::vector<PairType>;
  StorageContainer data;

public:
  using key_type = KeyType;
  using mapped_type = ValueType;
  using value_type = PairType;
  using size_type = typename StorageContainer::size_type;
  using difference_type = typename StorageContainer::difference_type;
  using reference = value_type &;
  using const_reference = const value_type &;
  using iterator = typename StorageContainer::iterator;
  using const_iterator = typename StorageContainer::const_iterator;

  SmallMap() = default;

  iterator Begin() noexcept { return data.begin(); }
  const_iterator Begin() const noexcept { return data.cbegin(); }
  const_iterator CBegin() const noexcept { return data.cbegin(); }

  iterator End() noexcept { return data.end(); }
  const_iterator End() const noexcept { return data.cend(); }
  const_iterator CEnd() const noexcept { return data.cend(); }

  // Capacity
  [[nodiscard]] bool IsEmpty() const noexcept { return data.empty(); }
  size_type GetSize() const noexcept { return data.size(); }

  mapped_type &operator[](const KeyType &Key) {
    auto it = Find(Key);
    if (it != End()) {
      return it->second;
    }
    data.emplace_back(Key, mapped_type{});
    return data.back().second;
  }

  mapped_type &operator[](KeyType &&Key) {
    auto it = Find(Key);
    if (it != End()) {
      return it->second;
    }
    data.emplace_back(std::move(Key), mapped_type{});
    return data.back().second;
  }

  template <typename K> mapped_type &At(const K &KeyToFind) {
    auto it = Find(KeyToFind);
    if (it != End()) { // Use non-const End()
      return it->second;
    }
    UNREACHABLE();
  }

  template <typename K> const mapped_type &At(const K &KeyToFind) const {
    auto it = Find(KeyToFind);
    if (it != CEnd()) { // Use const CEnd()
      return it->second;
    }
    UNREACHABLE();
  }

  template <typename K> iterator Find(const K &KeyToFind) {
    return std::find_if(data.begin(), data.end(),
                        [&KeyToFind](const PairType &CurrentPair) {
                          return CurrentPair.first == KeyToFind;
                        });
  }

  template <typename K> const_iterator Find(const K &KeyToFind) const {
    return std::find_if(data.cbegin(), data.cend(),
                        [&KeyToFind](const PairType &CurrentPair) {
                          return CurrentPair.first == KeyToFind;
                        });
  }

  template <typename K> bool Contains(const K &KeyToFind) const {
    return Find(KeyToFind) != CEnd();
  }

  void Clear() noexcept { data.clear(); }

  std::pair<iterator, bool> Insert(const value_type &Value) {
    const KeyType &key = Value.first;
    auto it = Find(key);
    if (it != End()) {
      return {it, false};
    }
    data.push_back(Value);
    return {std::prev(data.end()), true};
  }

  std::pair<iterator, bool> Insert(value_type &&Value) {
    const KeyType &key_for_find = Value.first;
    auto it = Find(key_for_find);
    if (it != End()) {
      return {it, false};
    }
    data.push_back(std::move(Value));
    return {std::prev(data.end()), true};
  }

  template <typename... ArgTypes>
  std::pair<iterator, bool> Emplace(ArgTypes &&...Args) {
    PairType temp_pair(std::forward<ArgTypes>(Args)...);
    const KeyType &key = temp_pair.first;

    auto it = Find(key);
    if (it != End()) {
      return {it, false};
    }
    data.push_back(std::move(temp_pair)); // Move the temp_pair instead
    return {std::prev(data.end()), true};
  }

  iterator Erase(const_iterator Pos) {
    difference_type dist = std::distance(data.cbegin(), Pos);
    auto it = data.begin();
    std::advance(it, dist);
    return data.erase(it);
  }

  iterator Erase(iterator Pos) { return data.erase(Pos); }

  template <typename K> size_type Erase(const K &KeyToErase) {
    auto it = Find(KeyToErase);
    if (it != End()) {
      data.erase(it);
      return 1;
    }
    return 0;
  }

  PairType &Front() { return data.front(); }

  PairType &Back() { return data.back(); }

  void ForEach(const std::function<void(const KeyType &, const ValueType &)>
                   &Func) const {
    for (const auto &pair : data) {
      Func(pair.first, pair.second);
    }
  }

  void Swap(SmallMap &Other) noexcept { data.swap(Other.data); }
};

template <typename KeyType, typename ValueType>
void Swap(SmallMap<KeyType, ValueType> &Lhs,
          SmallMap<KeyType, ValueType> &Rhs) noexcept {
  Lhs.Swap(Rhs);
}
