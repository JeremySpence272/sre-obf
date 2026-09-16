; Hand-written verifier regression: duplicate switch edges must contribute
; identical SSA values to each PHI, including across representation boundaries.
source_filename = "duplicate_edges.ll"
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @obf_target(i32 %x, i32 %y) {
entry:
  %sum = add i32 %x, %y
  %product = mul i32 %sum, %y
  switch i32 %y, label %other [i32 0, label %join
                              i32 1, label %join
                              i32 2, label %join]
other:
  %q = sub i32 %sum, 1
  br label %join
join:
  %value = phi i32 [%x, %entry], [%x, %entry], [%x, %entry], [%q, %other]
  %phase = phi i32 [%product, %entry], [%product, %entry], [%product, %entry], [%x, %other]
  %out = add i32 %value, %phase
  ret i32 %out
}
