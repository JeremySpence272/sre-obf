"""Executable specification and deliberately capable algebraic recovery control.

Mirrors the three flattening encodings at exactly 32 bits. Recoverability here
is intentional: these masks are NOT encryption with an unavailable secret.
Testing the model does not prove that emitted LLVM implements it correctly;
the compiled differential fixtures cover that separate boundary.
"""
MASK = (1 << 32) - 1


def rol(x: int, r: int) -> int:
    x &= MASK
    return ((x << r) | (x >> (32 - r))) & MASK


def encode(label: int, key: int, salt: int, family: int) -> int:
    if family == 0:
        return ((label ^ key) * (salt | 1) + rol(key, 11)) & MASK
    if family == 1:
        return rol((label + key) * (salt | 1), 9) ^ ((key + salt) & MASK)
    if family == 2:
        return ((rol(label ^ salt, 17) + key) * (key | 1)) & MASK
    raise ValueError("family must be 0..2")


def recover(token: int, key: int, salt: int, family: int) -> int:
    """Known-family recovery: a regression control, not an automated IR lifter."""
    if family == 0:
        return (((token - rol(key, 11)) * pow(salt | 1, -1, 1 << 32)) & MASK) ^ key
    if family == 1:
        product = rol(token ^ ((key + salt) & MASK), 23)
        return (product * pow(salt | 1, -1, 1 << 32) - key) & MASK
    if family == 2:
        rotated = (token * pow(key | 1, -1, 1 << 32) - key) & MASK
        return rol(rotated, 15) ^ salt
    raise ValueError("family must be 0..2")


def advance(token: int, key: int, salt: int, site0: int, site1: int):
    new_key = (rol(key ^ salt, 5) + site0) & MASK
    new_salt = rol(salt + token, 7) ^ ((new_key + site1) & MASK)
    return new_key, new_salt
