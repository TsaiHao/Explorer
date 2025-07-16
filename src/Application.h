#pragma once

#include <memory>
#include <string>

class Application {
public:
  explicit Application(std::string_view config);
  ~Application();

  void Run() const;

private:
  class Impl;
  std::unique_ptr<Impl> m_impl;
};
