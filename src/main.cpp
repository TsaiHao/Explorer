//
// Created by Hao, Zaijun on 2025/4/27.
//

#include <iostream>

#include "Application.h"
#include "utils/Log.h"
#include "utils/System.h"

int main(int argc, char *argv[]) {

  const Application app({argv, argv + argc});

  LOGI("Starting application");
  app.Run();

  return 0;
}