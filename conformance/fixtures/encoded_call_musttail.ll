; A private helper's body can contain musttail even when its callers do not.
; Its signature must remain compatible with the exported leaf's signature.
target triple = "x86_64-unknown-linux-gnu"

define i32 @leaf(i32 %x, i32 %y) noinline {
entry:
  %a = add i32 %x, %y
  %r = xor i32 %a, 91
  ret i32 %r
}

define internal i32 @tail_helper(i32 %x, i32 %y) noinline {
entry:
  %r = musttail call i32 @leaf(i32 %x, i32 %y)
  ret i32 %r
}

define i32 @obf_target(i32 %x, i32 %y) {
entry:
  %r = call i32 @tail_helper(i32 %x, i32 %y)
  ret i32 %r
}

; Non-returning and returns-twice helpers are also outside this private ABI.
; The driver never enters these diagnostic roots.
define internal i32 @never_returns(i32 %x) noreturn {
entry:
  unreachable
}

define internal i32 @returns_again(i32 %x) returns_twice noinline {
entry:
  ret i32 %x
}

define internal i32 @calls_twice(i32 %x) noinline {
entry:
  %r = call i32 @returns_again(i32 %x)
  ret i32 %r
}

define i32 @effect_roots(i32 %x, i1 %stop) {
entry:
  br i1 %stop, label %end, label %resume
end:
  %a = call i32 @never_returns(i32 %x)
  unreachable
resume:
  %b = call i32 @calls_twice(i32 %x)
  ret i32 %b
}
