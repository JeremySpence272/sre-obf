# v03 implementation and evidence ledger

Continuation of [v02](NATIVE_V02_PLAN.md), starting at `6d213a4`.
IR only; unchanged application sources; no VM, MC, post-link, environment,
anti-debugging, prompt or tokenizer work. This is an implementation ledger,
not a declaration of agent resistance or preset promotion.

## Scale correctness and compiler cost

The unchanged Lua failure was a compiler bug, not a hard analysis problem.
`luaV_execute` uses a global array of 83 block addresses. Transactional budget
rollback called `Function::deleteBody()` before rescuing those references;
LLVM replaced every table entry with `inttoptr(1)`. Cloning instructions back
did not restore the module-level table. The shared body transaction now moves
surviving block-address uses to its saved body, restores the function, and maps
those references back before destroying the snapshot. Both the ordinary driver
and connected-region budget enforcement use it. Newly generated module objects
still require separate ownership; this is not a general module transaction.

Compiler cost fixes avoid predecessor searches in functions without an EH
personality and replace repeated whole-module helper accounting with local
deltas plus a full stage-boundary recount. The helper profile cannot create
additional function bodies. Source-weight report iteration now follows module
order, not pointer-hash order. Limits were not increased.

Evidence, LLVM 22.1.8, seed 1, existing fair-budget v02 settings and 1,500,000 IR
instruction / 600-second per-command caps:

- `out/v03-rollback-r3`: repeated rollback, global jump table and recursion;
  three seeds, 593 complete outputs per native/post-O2 arm, all pass.
- `out/v03-rollback-old-control`: the retained failing Lua compiler triggers
  the regression's block-address corruption check, as expected.
- `out/scale-v03-lua-rollback`: unchanged workload and independent expected
  output pass. Obfuscation takes 126.99 seconds versus the prior 519.7 seconds;
  1,371,895 final instructions, 1,829 selected nodes, 492 predicates, 71
  flattened functions, **zero connected-memory edges**.
- `out/scale-v03-sqlite-helper-linear`: unchanged workload and independent
  expected output pass. Obfuscation takes 160.03 seconds versus the prior
  600-second timeout; 1,425,954 final instructions, 1,645 selected nodes,
  479 predicates, six memory edges, **zero surviving flattened functions**.
- `out/v03-stage-lua-control`: retained pre-application IR passes its workload
  through the diagnostic stage replayer. It is a dynamic-link diagnostic,
  separate from the static production lane, and is not sanitizer coverage.
- Existing Python unit suite: 29 tests pass.

These measurements close the two known build/correctness failures, not the
large-program coverage or overhead gates. All 513 SQLite flattening attempts
rolled back: proportional growth shares are too small to buy the transformation.
The next scale milestone must allocate usable structural budgets and report
actual coverage, rather than declaring the zero-coverage build protected.

## Next implementation batch

1. Scale policy: preserve measured structural work within the existing module
   cap; retain uniform allocation as an ablation. Add eligible/selected memory
   and structural denominators, cost and source-weighted coverage, with explicit
   failure when a requested gate has no surviving transformation.
2. Sol recovery regressions: freeze the successful v02 scripts privately;
   separate informed entry/state assumptions from binary-only discovery. Test
   dispatcher inversion, canonical-state rebasing and XOR/additive projection;
   distinguish unchanged transfer, repair, and unsupported/inconclusive tools.
3. P4: operation-compatible arithmetic/Boolean regions with verified direct
   cross-family transfers; remove avoidable plaintext multiplication bridges.
   Bounded genuine joint-output coupling is a separate ablation with an inverse
   control, not an assumed hardness benefit.
4. P5: bounded private encoded-call interfaces integrated with representations;
   preserve exported ABI, recursion/reentry, threads, and effect exclusions.
   Ordinary scalar helper wrappers are not encoded-ABI coverage.
5. Dispatch/activation experiments: regional dispatch relations and useful
   data/control representation dependencies. Canonical control resets must be
   tested with real live lanes, not only a known-zero witness. Keep inference
   and supplied-relation recovery arms.
6. Re-run full-output O0/O2 and post-O2 differentials, bounded reference proofs,
   compiler/decompiler normalization, seeds and unchanged large applications.
   Counterexamples fail; SMT unknown and decompiler errors are inconclusive.

No challenge name, address, flag, expected table, password length or diagnostic
string belongs in the production transformations. Algebraic recovery remains
possible; the target metric is reusable recovery cost, not binary size.
