; Def-use cycles must terminate; address observations and mandatory tail calls
; must not acquire activation-local storage.
target triple = "x86_64-unknown-linux-gnu"

@musttail_string = private constant [9 x i8] c"musttail\00"
@cycle_string = private constant [12 x i8] c"cycle-local\00"
@address_string = private constant [16 x i8] c"derived-address\00"
@select_string = private constant [14 x i8] c"select-escape\00"

declare i32 @puts(ptr captures(none))

define i32 @mandatory_tail(ptr %ignored) #0 {
  %v = musttail call i32 @puts(ptr @musttail_string)
  ret i32 %v
}

define void @cyclic_local(i1 %again) #0 {
entry:
  br label %loop
loop:
  %p = phi ptr [ @cycle_string, %entry ], [ %p, %loop ]
  %v = call i32 @puts(ptr %p)
  br i1 %again, label %loop, label %exit
exit:
  ret void
}

define i64 @derived_identity() #0 {
  %p = getelementptr [16 x i8], ptr @address_string, i64 0, i64 1
  %i = ptrtoint ptr %p to i64
  ret i64 %i
}

define ptr @selected_escape(i1 %which) #0 {
  %p = select i1 %which, ptr @select_string, ptr null
  ret ptr %p
}

attributes #0 = { "sre.native.spec"="obf: strenc(cipher=aes,minlen=1)" }
