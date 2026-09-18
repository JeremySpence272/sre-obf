"""Independent finite-phase storage model, including supplied-phase controls.

This models the law, not the C++ emitter. Native full-output differentials
separately check instantiated lowering. A supplied descriptor is not a secret.
"""


def layout(physical, phase):
    if phase not in (0, 1) or sorted(physical) != list(range(len(physical))):
        raise ValueError("invalid layout or phase")
    return tuple(physical[(k + phase) % len(physical)] for k in range(len(physical)))


def store(desc, state, carrier, phase, slot, pair):
    if phase not in (0, 1) or not 0 <= slot < len(state):
        raise ValueError("invalid phase or destination")
    bits, rotation = desc.bits, desc.rotations[-1]
    x = carrier ^ state[-1]
    history = ((x << rotation) | (x >> (desc.width - rotation))) & bits
    update = ((pair[0] ^ state[0]) + pair[1]) & bits
    next_phase = phase ^ 1
    next_carrier = ((history + update) ^ (next_phase * (desc.salts[0] | 1))) & bits
    new = []
    for k in range(len(state)):
        e, r = pair if k == slot else (state[k], desc.mask(state, carrier, k))
        m = desc.mask(new, next_carrier, k)
        new.append(((e + m - r) if desc.additive else (e ^ r ^ m)) & bits)
    return tuple(new), next_carrier, next_phase
