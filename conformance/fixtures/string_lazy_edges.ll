; Runtime regressions for a critical PHI edge and a two-entry loop.
target triple = "x86_64-unknown-linux-gnu"

@phi_left = private constant [9 x i8] c"phi-left\00"
@phi_right = private constant [10 x i8] c"phi-right\00"
@cycle_use = private constant [10 x i8] c"cycle-use\00"
declare i32 @puts(ptr captures(none))

define void @lazy_phi(i32 %which) #0 {
entry:
  switch i32 %which, label %exit [ i32 1, label %join
                                  i32 2, label %join
                                  i32 3, label %other ]
other:
  br label %join
join:
  %p = phi ptr [ @phi_left, %entry ], [ @phi_left, %entry ], [ @phi_right, %other ]
  %r = call i32 @puts(ptr %p)
  br label %exit
exit:
  ret void
}

define void @lazy_cycle(i32 %which) #0 {
entry:
  %n = alloca i32
  store i32 4, ptr %n
  switch i32 %which, label %exit [ i32 1, label %a
                                  i32 2, label %b ]
a:
  %r = call i32 @puts(ptr @cycle_use)
  %av = load i32, ptr %n
  %ad = sub i32 %av, 1
  store i32 %ad, ptr %n
  %ac = icmp sgt i32 %ad, 0
  br i1 %ac, label %b, label %exit
b:
  %bv = load i32, ptr %n
  %bd = sub i32 %bv, 1
  store i32 %bd, ptr %n
  %bc = icmp sgt i32 %bd, 0
  br i1 %bc, label %a, label %exit
exit:
  ret void
}

attributes #0 = { "sre.native.spec"="obf: strenc(cipher=aes,minlen=1,keysplit=1)" }
