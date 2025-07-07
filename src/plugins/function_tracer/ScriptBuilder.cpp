//
// Created by Hao, Zaijun on 2025/7/1.
//

#include "ScriptBuilder.h"

namespace plugin {
namespace {
constexpr std::string_view kNativeTracerScriptTamplate = R"(
    
    )";
}

std::string ScriptBuilder::Build() const {
  return std::string(kNativeTracerScriptTamplate);
}
} // namespace plugin