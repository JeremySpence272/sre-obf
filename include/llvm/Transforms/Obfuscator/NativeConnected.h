#pragma once
#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"

namespace llvm::obf {
struct NativeConnectedOptions {
  unsigned Nodes = 128;
  bool Memory = false;
  bool Predicates = false;
  bool Families = false;
  bool CoupleState = false;
  bool Invariant = false;
};
json::Array encodeNativeConnected(Module &, uint64_t, const NativeConnectedOptions &);
json::Array absorbNativeSupport(Module &);
}
