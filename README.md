# sre-obf

sre-obf is a fork of xollvm focused on native, whole-program, representation-aware LLVM obfuscation.

- **Strong native profile:** constant encoding, MBA, substitution, block splitting, semantic diffusion, bogus control flow, flattening, indirect calls, string encryption, function merging, anti-optimization, and anti-decompiler passes.
- **Seeded encoding families:** XOR/additive shares, rotations, odd multiplication, and mixed-family conversions for constants and values.
- **Persistent encoded dataflow:** arithmetic, Boolean logic, shifts, casts, PHIs, selects, comparisons, and connected computation regions.
- **Encoded memory objects:** locals, arrays, aggregates, immutable tables, and small coupled tiles, including rekeying and permutation across updates.
- **Relational control-flow flattening:** per-activation multiword state, history-dependent transitions, multiple dispatchers, fake transitions, and encoded state pointers.
- **Data/control coupling:** live encoded values influence dispatcher state and predicates rather than remaining separate layers.
- **Joint value bundles:** related values remain encoded together across computations, loops, recurrence phases, predicates, and outputs.
- **Interprocedural continuity:** function fusion, outlining, merging, encoded private-call arguments/results, joint argument tuples, recursion, and limited encoded-object borrowing.
- **Generated-code hardening:** decoders, constructors, call-table initializers, thunks, and other compiler-created helpers.
- **Attack-guided selection:** deterministic seeds, typed planning, explicit boundaries, growth budgets, rollback, coverage accounting, and measured encoding-family selection.

Crackme test results:
- unobfuscated baseline was solved in 8 steps and 34 seconds
- current v4 build was solved in ~400 steps and 14h 47m 50s
