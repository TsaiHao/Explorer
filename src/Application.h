#pragma once

#include "TaskConfig.h"

class Application {
public:
  explicit Application(TaskConfig config);
  ~Application();

  void Run() const;
private:
  class Impl;
  std::unique_ptr<Impl> mImpl;
};
