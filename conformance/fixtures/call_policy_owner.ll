; A recorded owner must survive even if merging leaves the function alone.
; This is a compiler regression, not a new member of the locked tuning corpus.
target triple = "x86_64-unknown-linux-gnu"

define internal i32 @helper(i32 %x, i32 %y) #0 {
  %a = add i32 %x, 31
  %b = xor i32 %a, %y
  %c = mul i32 %b, 7
  %d = lshr i32 %c, 3
  %e = xor i32 %c, %d
  ret i32 %e
}

define i32 @obf_target(i32 %x, i32 %y) {
  %a = call i32 @helper(i32 %x, i32 %y)
  %b = add i32 %a, %x
  %c = xor i32 %b, %y
  ret i32 %c
}

attributes #0 = { noinline "sre.native.policy"="scalar-boundary" }
