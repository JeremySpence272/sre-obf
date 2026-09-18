#include "llvm/Transforms/Obfuscator/NativeBundlePolicy.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"

using namespace llvm;
namespace llvm::obf {
namespace {
[[noreturn]] void invalid(StringRef Why) {
  report_fatal_error(Twine("native bundle policy: ") + Why);
}
void keys(const json::Object &O, std::initializer_list<StringRef> Names) {
  if (O.size() != Names.size()) invalid("missing or unknown fields");
  for (StringRef Name : Names) if (!O.get(Name)) invalid("missing field");
}
unsigned integer(const json::Object &O, StringRef Key, unsigned Low, unsigned High) {
  auto N = O.getInteger(Key);
  if (!N || *N < Low || *N > High) invalid("out-of-range shape field");
  return unsigned(*N);
}
}

NativeBundlePolicy NativeBundlePolicy::load(StringRef Path) {
  uint64_t Size = 0;
  if (sys::fs::file_size(Path, Size) || Size > 65536) invalid("file missing or exceeds 64 KiB");
  auto Buffer = MemoryBuffer::getFile(Path);
  if (!Buffer) invalid("cannot read file");
  StringRef Bytes = (*Buffer)->getBuffer();
  if (Bytes.size() > 65536) invalid("file exceeds 64 KiB");
  auto Parsed = json::parse(Bytes);
  if (!Parsed) { consumeError(Parsed.takeError()); invalid("invalid JSON"); }
  const auto *Root = Parsed->getAsObject();
  if (!Root) invalid("expected object");
  keys(*Root, {"schema", "evidence_sha256", "rules"});
  if (Root->getString("schema") != "sre-bundle-policy-v1") invalid("unsupported schema");
  auto Evidence = Root->getString("evidence_sha256");
  if (!Evidence || Evidence->size() != 64 ||
      !llvm::all_of(*Evidence, [](char C) { return (C >= '0' && C <= '9') || (C >= 'a' && C <= 'f'); }))
    invalid("invalid evidence digest");
  const auto *Rows = Root->getArray("rules");
  if (!Rows || Rows->size() > 128) invalid("expected at most 128 rules");
  NativeBundlePolicy P;
  P.SHA256 = toHex(llvm::SHA256::hash(arrayRefFromStringRef(Bytes)), true);
  P.EvidenceSHA256 = Evidence->str();
  for (const json::Value &V : *Rows) {
    const auto *R = V.getAsObject();
    if (!R) invalid("expected rule object");
    keys(*R, {"shape", "candidates"});
    const auto *S = R->getObject("shape");
    if (!S) invalid("expected shape object");
    keys(*S, {"width", "lanes", "nodes", "pins"});
    Rule Row{integer(*S, "width", 8, 64), integer(*S, "lanes", 2, 4),
             integer(*S, "nodes", 8, 32), false, {}};
    if (Row.Width != 8 && Row.Width != 16 && Row.Width != 32 && Row.Width != 64)
      invalid("unsupported width");
    auto Pins = S->getBoolean("pins");
    if (!Pins) invalid("pins must be Boolean");
    Row.Pins = *Pins;
    if (P.match(Row.Width, Row.Lanes, Row.Nodes, Row.Pins)) invalid("duplicate shape");
    const auto *Candidates = R->getArray("candidates");
    if (!Candidates || Candidates->empty() || Candidates->size() > 2)
      invalid("expected one or two candidates");
    for (const json::Value &Candidate : *Candidates) {
      auto Name = Candidate.getAsString();
      if (!Name || (*Name != "xor" && *Name != "additive")) invalid("unknown candidate");
      if (llvm::is_contained(Row.Candidates, *Name)) invalid("duplicate candidate");
      Row.Candidates.push_back(Name->str());
    }
    llvm::sort(Row.Candidates);
    P.Rules.push_back(std::move(Row));
  }
  return P;
}

const NativeBundlePolicy::Rule *NativeBundlePolicy::match(
    unsigned Width, unsigned Lanes, unsigned Nodes, bool Pins) const {
  for (const Rule &R : Rules)
    if (R.Width == Width && R.Lanes == Lanes && R.Nodes == Nodes && R.Pins == Pins) return &R;
  return nullptr;
}

json::Object NativeBundlePolicy::identity() const {
  return json::Object{{"schema", "sre-bundle-policy-v1"}, {"sha256", SHA256},
          {"evidence_sha256", EvidenceSHA256}, {"rules", Rules.size()},
          {"scope", "straight-pure-bundle-family"}, {"hardness_evaluated", false}};
}
}
