; Router edges must not leave these non-entry allocation pointers as SSA uses
; outside their defining block. This models merged bodies and variable arrays.
target triple = "x86_64-unknown-linux-gnu"

declare void @llvm.lifetime.start.p0(ptr nocapture)
declare void @llvm.lifetime.end.p0(ptr nocapture)

define i32 @obf_target(i32 %x, i32 %y) {
entry:
  %choose = icmp eq i32 %x, 0
  br i1 %choose, label %short, label %allocate
short:
  ret i32 %y
allocate:
  %n0 = and i32 %y, 15
  %n = add i32 %n0, 1
  %array = alloca i32, i32 %n, align 4
  %scalar = alloca i32, align 4
  call void @llvm.lifetime.start.p0(ptr %scalar)
  store volatile i32 %x, ptr %array, align 4
  store volatile i32 %y, ptr %scalar, align 4
  %condition = icmp ult i32 %x, %y
  br i1 %condition, label %left, label %right
left:
  %a = load volatile i32, ptr %array, align 4
  %l = add i32 %a, %y
  br label %done
right:
  %b = load volatile i32, ptr %scalar, align 4
  %r = xor i32 %b, %x
  br label %done
done:
  %result = phi i32 [ %l, %left ], [ %r, %right ]
  call void @llvm.lifetime.end.p0(ptr %scalar)
  ret i32 %result
}
