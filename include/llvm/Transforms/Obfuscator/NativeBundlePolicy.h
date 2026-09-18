#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/JSON.h"
#include <string>
#include <vector>

namespace llvm::obf {
// Selects verified emitters, never new expressions or higher budgets.
struct NativeBundlePolicy {
  struct Rule {
    unsigned Width, Lanes, Nodes;
    bool Pins;
    std::vector<std::string> Candidates;
  };
  std::string SHA256, EvidenceSHA256;
  std::vector<Rule> Rules;
  static NativeBundlePolicy load(StringRef Path);
  const Rule *match(unsigned Width, unsigned Lanes, unsigned Nodes, bool Pins) const;
  json::Object identity() const;
};
}
