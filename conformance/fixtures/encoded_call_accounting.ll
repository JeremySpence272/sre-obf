; An existing suffix symbol forces LLVM to uniquify the encoded callee name.
; Only one parameter loses all scalar uses; x still feeds unsupported udiv.
target triple = "x86_64-unknown-linux-gnu"

declare void @mixed.sre.encoded()

define internal i32 @mixed(i32 %x, i32 %y) noinline {
entry:
  %a = add i32 %x, %y
  %b = xor i32 %a, 19
  %q = udiv i32 %x, 3
  %r = add i32 %b, %q
  ret i32 %r
}

define i32 @obf_target(i32 %x, i32 %y) {
entry:
  %r = call i32 @mixed(i32 %x, i32 %y)
  ret i32 %r
}
