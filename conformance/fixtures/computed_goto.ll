; A body-only budget rollback must preserve addresses held by global constants.
; Also exercise recursive references after multiple passes roll back one body.
target triple = "x86_64-unknown-linux-gnu"

@targets = internal constant [2 x ptr] [ptr blockaddress(@dispatch, %left), ptr blockaddress(@dispatch, %right)]

define internal i32 @dispatch(i32 %x, i32 %y, i32 %depth) #0 {
entry:
  %index = and i32 %x, 1
  %slot = getelementptr [2 x ptr], ptr @targets, i32 0, i32 %index
  %target = load ptr, ptr %slot
  indirectbr ptr %target, [label %left, label %right]
left:
  %a0 = add i32 %x, %y
  %a = xor i32 %a0, 305419896
  br label %join
right:
  %b0 = xor i32 %x, %y
  %b = add i32 %b0, 1732584193
  br label %join
join:
  %value = phi i32 [ %a, %left ], [ %b, %right ]
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %exit, label %recurse
recurse:
  %next = sub i32 %depth, 1
  %r = call i32 @dispatch(i32 %y, i32 %value, i32 %next)
  ret i32 %r
exit:
  ret i32 %value
}

define i32 @obf_target(i32 %x, i32 %y) {
  %d = and i32 %x, 3
  %r = call i32 @dispatch(i32 %x, i32 %y, i32 %d)
  ret i32 %r
}

attributes #0 = { "sre.native.spec"="obf: constenc(prob=100,maxSites=100,wrapMBA=1),sdiff(prob=100,slots=4,maxSites=100),shield(maxSites=100)" }
