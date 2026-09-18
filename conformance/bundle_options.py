"""One option contract shared by fixture, whole-program and scale drivers."""


def add_options(parser):
    parser.add_argument("--bundles", action="store_true")
    parser.add_argument("--object-bundles", action="store_true")
    parser.add_argument("--object-phases", action="store_true")
    parser.add_argument("--object-max-cells", type=int, choices=(4, 8))
    parser.add_argument("--immutable-bundles", action="store_true")
    parser.add_argument("--continuity-priority", action="store_true")
    parser.add_argument("--bundle-call-inputs", action="store_true")
    parser.add_argument("--bundle-call-outputs", action="store_true")
    parser.add_argument("--joint-call-arguments", action="store_true")
    parser.add_argument("--bundle-control", action="store_true")
    parser.add_argument("--bundle-predicates", action="store_true")
    parser.add_argument("--transfer-family", choices=("xor", "additive", "seeded"))
    parser.add_argument("--bundle-values", type=int, choices=(2, 3, 4))
    parser.add_argument("--transfer-nodes", type=int, choices=range(8, 33))
    parser.add_argument("--no-bundle-pins", action="store_true")
    parser.add_argument("--bundle-loops", action="store_true")
    parser.add_argument("--bundle-phases", action="store_true")
    parser.add_argument("--bundle-loop-boundaries", action="store_true")


def validate(args, connected):
    enabled = getattr(args, "bundles", False)
    choices = any(getattr(args, key, None) is not None
                  for key in ("transfer_family", "bundle_values", "transfer_nodes", "object_max_cells"))
    switches = any(getattr(args, key, False) for key in
                   ("no_bundle_pins", "bundle_loops", "bundle_phases", "bundle_loop_boundaries",
                    "object_bundles", "object_phases", "immutable_bundles", "continuity_priority", "bundle_call_inputs", "bundle_call_outputs", "joint_call_arguments", "bundle_control", "bundle_predicates"))
    if not enabled and (choices or switches):
        raise ValueError("bundle options require --bundles")
    if getattr(args, "object_phases", False) and not getattr(args, "object_bundles", False):
        raise ValueError("--object-phases requires --object-bundles")
    if getattr(args, "object_max_cells", None) is not None and not getattr(args, "object_bundles", False):
        raise ValueError("--object-max-cells requires --object-bundles")
    if getattr(args, "bundle_call_inputs", False) and not getattr(args, "encoded_calls", False):
        raise ValueError("--bundle-call-inputs requires --encoded-calls")
    if getattr(args, "bundle_call_outputs", False) and not getattr(args, "encoded_calls", False):
        raise ValueError("--bundle-call-outputs requires --encoded-calls")
    if getattr(args, "joint_call_arguments", False) and not getattr(args, "encoded_calls", False):
        raise ValueError("--joint-call-arguments requires --encoded-calls")
    if getattr(args, "bundle_control", False) and not getattr(args, "bundle_loops", False):
        raise ValueError("--bundle-control requires --bundle-loops")
    if getattr(args, "bundle_control", False) and getattr(args, "no_multistate", False):
        raise ValueError("--bundle-control requires multi-state flattening")
    if getattr(args, "bundle_phases", False) and not getattr(args, "bundle_loops", False):
        raise ValueError("--bundle-phases requires --bundle-loops")
    if getattr(args, "bundle_loop_boundaries", False) and not getattr(args, "bundle_loops", False):
        raise ValueError("--bundle-loop-boundaries requires --bundle-loops")
    if enabled and not connected:
        raise ValueError("--bundles requires the connected planner")


def flags(args):
    if not getattr(args, "bundles", False): return []
    return ["-native-bundles=1",
            f"-native-transfer-family={getattr(args, 'transfer_family', None) or 'seeded'}",
            f"-native-bundle-values={getattr(args, 'bundle_values', None) or 4}",
            f"-native-transfer-nodes={getattr(args, 'transfer_nodes', None) or 16}",
            f"-native-bundle-pins={int(not getattr(args, 'no_bundle_pins', False))}"] + (
            [f"-native-object-max-cells={args.object_max_cells}"] if getattr(args, "object_max_cells", None) is not None else []) + [
            "-native-" + key.replace("_", "-") + "=1"
            for key in ("bundle_loops", "bundle_phases", "bundle_loop_boundaries",
                        "object_bundles", "object_phases", "immutable_bundles", "continuity_priority", "bundle_call_inputs", "bundle_call_outputs", "joint_call_arguments", "bundle_control", "bundle_predicates")
            if getattr(args, key, False)]


def argv(args):
    if not getattr(args, "bundles", False): return []
    out = ["--bundles"]
    for name in ("transfer_family", "bundle_values", "transfer_nodes", "object_max_cells"):
        if getattr(args, name, None) is not None:
            out += ["--" + name.replace("_", "-"), str(getattr(args, name))]
    if getattr(args, "no_bundle_pins", False): out.append("--no-bundle-pins")
    for name in ("bundle_loops", "bundle_phases", "bundle_loop_boundaries",
                 "object_bundles", "object_phases", "immutable_bundles", "continuity_priority", "bundle_call_inputs", "bundle_call_outputs", "joint_call_arguments", "bundle_control", "bundle_predicates"):
        if getattr(args, name, False): out.append("--" + name.replace("_", "-"))
    return out
