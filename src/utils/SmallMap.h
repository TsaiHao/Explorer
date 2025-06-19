#pragma once

#include <algorithm>
#include <functional>
#include <iterator>
#include <utility>
#include <vector>

#define THROW

template <typename KeyType, typename ValueType> class SmallMap {
  using PairType = std::pair<KeyType, ValueType>;
  using StorageContainer = std::vector<PairType>;
  StorageContainer Data;

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

  iterator Begin() noexcept { return Data.begin(); }
  const_iterator Begin() const noexcept { return Data.cbegin(); }
  const_iterator CBegin() const noexcept { return Data.cbegin(); }

  iterator End() noexcept { return Data.end(); }
  const_iterator End() const noexcept { return Data.cend(); }
  const_iterator CEnd() const noexcept { return Data.cend(); }

  // Capacity
  [[nodiscard]] bool IsEmpty() const noexcept { return Data.empty(); }
  size_type GetSize() const noexcept { return Data.size(); }

  mapped_type &operator[](const KeyType &Key) {
    auto it = Find(Key);
    if (it != End()) {
      return it->second;
    }
    Data.emplace_back(Key, mapped_type{});
    return Data.back().second;
  }

  mapped_type &operator[](KeyType &&Key) {
    auto it = Find(Key);
    if (it != End()) {
      return it->second;
    }
    Data.emplace_back(std::move(Key), mapped_type{});
    return Data.back().second;
  }

  template <typename K> mapped_type &At(const K &KeyToFind) {
    auto it = Find(KeyToFind);
    if (it != End()) { // Use non-const End()
      return it->second;
    }
    std::unreachable();
  }

  template <typename K> const mapped_type &At(const K &KeyToFind) const {
    auto it = Find(KeyToFind);
    if (it != CEnd()) { // Use const CEnd()
      return it->second;
    }
    std::unreachable();
  }

  template <typename K> iterator Find(const K &KeyToFind) {
    return std::find_if(Data.begin(), Data.end(),
                        [&KeyToFind](const PairType &CurrentPair) {
                          return CurrentPair.first == KeyToFind;
                        });
  }

  template <typename K> const_iterator Find(const K &KeyToFind) const {
    return std::find_if(Data.cbegin(), Data.cend(),
                        [&KeyToFind](const PairType &CurrentPair) {
                          return CurrentPair.first == KeyToFind;
                        });
  }

  template <typename K> bool Contains(const K &KeyToFind) const {
    return Find(KeyToFind) != CEnd();
  }

  void Clear() noexcept { Data.clear(); }

  std::pair<iterator, bool> Insert(const value_type &Value) {
    const KeyType &key = Value.first;
    auto it = Find(key);
    if (it != End()) {
      return {it, false};
    }
    Data.push_back(Value);
    return {std::prev(Data.end()), true};
  }

  std::pair<iterator, bool> Insert(value_type &&Value) {
    const KeyType &key_for_find = Value.first;
    auto it = Find(key_for_find);
    if (it != End()) {
      return {it, false};
    }
    Data.push_back(std::move(Value));
    return {std::prev(Data.end()), true};
  }

  template <typename... ArgTypes>
  std::pair<iterator, bool> Emplace(ArgTypes &&...Args) {
    PairType temp_pair_for_key_extraction(std::forward<ArgTypes>(Args)...);
    const KeyType &key = temp_pair_for_key_extraction.first;

    auto it = Find(key);
    if (it != End()) {
      return {it, false};
    }
    Data.emplace_back(std::forward<ArgTypes>(Args)...);
    return {std::prev(Data.end()), true};
  }

  iterator Erase(const_iterator Pos) {
    difference_type dist = std::distance(Data.cbegin(), Pos);
    auto it = Data.begin();
    std::advance(it, dist);
    return Data.erase(it);
  }

  iterator Erase(iterator Pos) { return Data.erase(Pos); }

  template <typename K> size_type Erase(const K &KeyToErase) {
    auto it = Find(KeyToErase);
    if (it != End()) {
      Data.erase(it);
      return 1;
    }
    return 0;
  }

  PairType &Front() { return Data.front(); }

  PairType &Back() { return Data.back(); }

  void ForEach(const std::function<void(const KeyType &, const ValueType &)>
                   &Func) const {
    for (const auto &pair : Data) {
      Func(pair.first, pair.second);
    }
  }

  void Swap(SmallMap &Other) noexcept { Data.swap(Other.Data); }
};

template <typename KeyType, typename ValueType>
void Swap(SmallMap<KeyType, ValueType> &Lhs,
          SmallMap<KeyType, ValueType> &Rhs) noexcept {
  Lhs.Swap(Rhs);
}
