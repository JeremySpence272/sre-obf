"""Runtime representation switches shared by whole-program and RevGame builds."""


def add_options(parser):
    parser.add_argument("--selective-interpreter", action="store_true")
    parser.add_argument("--exact-consumers", action="store_true")
    parser.add_argument("--runtime-buffers", action="store_true")
    parser.add_argument("--runtime-state", action="store_true")
    parser.add_argument("--runtime-single-thread", action="store_true")
    parser.add_argument("--runtime-phases", action="store_true")
    parser.add_argument("--runtime-getters", action="store_true")
    parser.add_argument("--runtime-growth", type=int, default=None)
    parser.add_argument("--runtime-test-seed", type=int, default=None)


def validate(args):
    enabled = args.runtime_state
    if enabled and not args.runtime_single_thread:
        raise ValueError("--runtime-state requires --runtime-single-thread")
    if not enabled and (args.runtime_single_thread or args.runtime_phases or args.runtime_getters or args.runtime_buffers or
                        args.runtime_growth is not None or args.runtime_test_seed is not None):
        raise ValueError("runtime controls require --runtime-state")
    if args.runtime_growth is not None and not 1 <= args.runtime_growth <= 65536:
        raise ValueError("--runtime-growth must be 1..65536")
    if args.runtime_test_seed is not None and not 0 <= args.runtime_test_seed < 2**64:
        raise ValueError("--runtime-test-seed must be an unsigned 64-bit integer")


def flags(args):
    extra = ["-native-exact-consumers=1"] if args.exact_consumers else []
    if args.selective_interpreter:
        extra.append("-native-interpreter=1")
    if not args.runtime_state:
        return extra
    result = ["-native-runtime-state=1", "-native-runtime-single-thread=1",
              f"-native-runtime-phases={int(args.runtime_phases)}"]
    result.append(f"-native-runtime-buffers={int(args.runtime_buffers)}")
    result.append(f"-native-runtime-getters={int(args.runtime_getters)}")
    for name in ("runtime_growth", "runtime_test_seed"):
        value = getattr(args, name)
        if value is not None:
            result.append("-native-" + name.replace("_", "-") + "=" + str(value))
    return extra + result
