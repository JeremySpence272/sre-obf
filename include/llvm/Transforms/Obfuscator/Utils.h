#pragma once
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContext.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Instructions.h"
#include <unordered_map>
#include <vector>
#include <string>




namespace llvm::obf {

	// ----------------------------------------------------------------------
	// Obfuscator-generated function marker
	//
	// Functions the obfuscator synthesizes mid-pipeline (e.g. the VM's
	// __vm_engine interpreter, handler thunks, anti-debug/crypto helpers)
	// must never be re-driven by ObfuscationFunctionDriverPass: they carry
	// no source annotation, and re-running analyses/passes on them is at
	// best wasteful and at worst fatal (the 100k+ instruction VM engine).
	//
	// LLVM's function-pass adaptor iterates the module's function list, and
	// on LLVM 23 it visits functions appended during that same iteration, so
	// the driver would otherwise pick up these generated functions. We tag
	// them at creation and early-return for them at the driver entry.
	constexpr const char* GeneratedFnAttr = "obf-generated";

	inline void markObfGenerated(llvm::Function& F) {
		F.addFnAttr(GeneratedFnAttr);
	}
	inline bool isObfGenerated(const llvm::Function& F) {
		return F.hasFnAttribute(GeneratedFnAttr);
	}

	std::vector<std::string> readAnnotations(llvm::Function* F);

	llvm::Value* getObfEntropyI32(llvm::IRBuilder<>& B);

	llvm::Value* getObfEntropyI32Stable(llvm::IRBuilder<>& B);

	llvm::AllocaInst* ensureEntropyAllocaAtEntryBegin(Function& F);

	llvm::Value* getSDiffEntropyI32(IRBuilder<>& B, Value* AnchorPtr);


	// Create (or reuses) a per-function volatile i32 slot used as an 'optimizer-resistant'
	// entropy anchor. The slot is initialized in the entry block.
	AllocaInst* getOrCreateVolatileI32Slot(Function& F, StringRef Name, Rng& R);

	// Builds a value that is *runtime equal to 0* but cannot be folded dur to volatile loads.
	Value* makeRuntimeZero(IRBuilder<>& B, AllocaInst* VolSlot, unsigned BitWidth, Rng& R, StringRef Tag);

	// Optionally mixes runtime-zero into V via XOR (preserves semantics).
	Value* xorWithRuntimeZero(IRBuilder<>& B, Value* V, AllocaInst* VolSlot, Rng& R, StringRef Tag, unsigned Prob = 50);


	// Best insertion point for new allocas in entry (after PHI/Dbg/Alloca group).
	llvm::Instruction* getAllocaIP(llvm::Function& F);

	// Strategy A helper: localize reg2mem only for CFG safety (PHIs + escaping regs), then mem2reg after.
	// - Demotes PHIs + escaping regs into fresh entry allocas.
	// - Adds an entry initialization store (null) for each new alloca to prevent undef/UB on "imaginary" CFG paths.
	// - Returns the list of newly created allocas so the caller can mem2reg them after CFG rewrite.
	bool demoteForCFGChange(llvm::Function& F, llvm::SmallVectorImpl<llvm::AllocaInst*>& OutNewAllocas);
	bool promoteDemotedAllocas(llvm::Function& F, llvm::ArrayRef<llvm::AllocaInst*> NewAllocas);


	// global SSA/dominance repair (reg2mem)
	bool repairSSA(Function& F);


	// ----------------------------------------------------------------------
	// Pass skip channel
	//
	// A pass that decides to bail out (e.g. eligibility check failed,
	// candidate set empty) records a structured skip reason via this helper.
	// The driver reads `FOC.PassSkipReasons` after the pass returns and:
	//   - marks the IRBudget record as Skipped + SkipReason
	//   - flushes into the per-pass JSON report
	//   - aborts with report_fatal_error when `-obf-no-skips` is enabled
	//
	// `passId` should be the canonical pass id (e.g. "vm", "flattening").
	// `reason` should be a short stable token (e.g. "eh_unsupported",
	// "callbr", "too_few_blocks") suitable for matching in tests.
	// Repeated calls for the same passId on the same function overwrite
	// the previous reason (last wins).
	void recordObfPassSkip(llvm::FunctionObfContext& FOC,
		llvm::StringRef passId,
		llvm::StringRef reason);


} // namespace llvm::obf

