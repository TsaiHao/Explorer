#pragma once

#include <memory>
#include <string>
#include <vector>

class Application {
public:
  explicit Application(const std::vector<std::string_view> &args);
  ~Application();

  void Run() const;

private:
  class Impl;
  std::unique_ptr<Impl> m_impl;
};
