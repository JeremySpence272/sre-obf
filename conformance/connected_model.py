"""Bit-precise reference for connected XOR transfers, not a compiler proof."""

def operations(width, logical_shift=lambda value, amount: value >> amount):
    mask = (1 << width) - 1
    def xor(x, y): return (x[0] ^ y[0], x[1] ^ y[1])
    def inv(x): return (x[0] ^ mask, x[1])
    def land(x, y):
        e = (x[0] & y[0]) ^ (x[0] & y[1]) ^ (x[1] & y[0])
        return (e, x[1] & y[1])
    def lor(x, y): return xor(xor(x, y), land(x, y))
    def shl(x, d): return ((x[0] << d) & mask, (x[1] << d) & mask)
    def lshr(x, d): return (logical_shift(x[0], d), logical_shift(x[1], d))
    return xor, inv, land, lor, shl, lshr


def add(x, y, width, carry=False, logical_shift=lambda value, amount: value >> amount):
    xor, inv, land, lor, shl, lshr = operations(width, logical_shift)
    p = original = xor(x, y)
    if carry: original = (original[0] ^ 1, original[1])
    if width == 1: return original
    g = land(x, y)
    if carry: g = lor(g, land(p, (1, 0)))
    d = 1
    while d < width:
        g = lor(g, land(p, shl(g, d)))
        if d * 2 < width: p = land(p, shl(p, d))
        d *= 2
    return xor(original, shl(g, 1))


def compare(x, y, width, signed=False, equality=False, logical_shift=lambda value, amount: value >> amount):
    xor, inv, land, lor, shl, lshr = operations(width, logical_shift)
    if equality:
        z = xor(x, y)
        d = 1
        while d < width:
            z = lor(z, lshr(z, d)); d *= 2
        return ((z[0] & 1) ^ 1, z[1] & 1)
    p, g = inv(xor(x, y)), land(inv(x), y)
    d = 1
    while d < width:
        g = lor(g, land(p, shl(g, d)))
        p = land(p, shl(p, d)); d *= 2
    low = lambda a: (a[0] & 1, a[1] & 1)
    result = low(lshr(g, width - 1))
    if not signed:
        return result
    sx, sy = low(lshr(x, width - 1)), low(lshr(y, width - 1))
    bxor, bnot, band, bor, _, _ = operations(1)
    different = bxor(sx, sy)
    return bor(band(different, sx), band(bnot(different), result))


def xor_to_additive(x, refresh, width):
    mask = (1 << width) - 1
    return ((x[0] + x[1] - 2 * (x[0] & x[1]) + refresh) & mask, refresh & mask)


def xor_to_additive_grouped(x, refresh, width):
    """`xor_to_additive` reassociated so no intermediate is the plain value.

    The v03 form computes `x0 + x1 - 2*(x0 & x1)` and only then adds the
    refresh; that subexpression is exactly `x0 ^ x1`, so the decoded value
    exists in a register between two inverses. Adding the refresh first is the
    same function of the same operands -- the identity a + b = (a ^ b) + 2*(a&b)
    holds in the ring -- with no such intermediate.
    """
    mask = (1 << width) - 1
    return ((((x[0] + refresh) + x[1]) - 2 * (x[0] & x[1])) & mask, refresh & mask)


def affine_mul_grouped(x, y, width):
    """The v03 additive product, regrouped so no intermediate is the product.

    The v03 form is `ex*ey - (ex*s + ey*r) + r*s` and only then `+ (r^s)`; that
    subexpression is exactly x*y, so the plain product exists in a register
    between two inverses. Adding the output mask to the first partial product
    instead gives the same value with no such intermediate.
    """
    mask = (1 << width) - 1
    r, s = x[1], y[1]
    refresh = r ^ s
    return (((x[0] * y[0] + refresh) - (x[0] * s + y[0] * r) + r * s) & mask, refresh & mask)


def pair_add(x, y, width, affine, logical_shift=lambda value, amount: value >> amount):
    """Add two encoded pairs of one family without decoding either of them."""
    mask = (1 << width) - 1
    if affine:
        return ((x[0] + y[0]) & mask, (x[1] + y[1]) & mask)
    return add(x, y, width, False, logical_shift)


def pair_sub(x, y, width, affine, logical_shift=lambda value, amount: value >> amount):
    mask = (1 << width) - 1
    if affine:
        return ((x[0] - y[0]) & mask, (x[1] - y[1]) & mask)
    _, inv, *_ = operations(width, logical_shift)
    return add(x, inv(y), width, True, logical_shift)


def pair_double(x, width, affine, logical_shift=lambda value, amount: value >> amount):
    """Doubling as a pair addition: a one-bit shift by one would be poison."""
    return pair_add(x, x, width, affine, logical_shift)


def joint_mix(x, y, width, affine, logical_shift=lambda value, amount: value >> amount):
    """Joint outputs U = X + Y and V = X + 2Y as encoded pairs."""
    u = pair_add(x, y, width, affine, logical_shift)
    v = pair_add(x, pair_double(y, width, affine, logical_shift), width, affine, logical_shift)
    return u, v


def joint_unmix(u, v, width, affine, logical_shift=lambda value, amount: value >> amount):
    """The exact inverse X = 2U - V, Y = V - U; the matrix has determinant one."""
    x = pair_sub(pair_double(u, width, affine, logical_shift), v, width, affine, logical_shift)
    y = pair_sub(v, u, width, affine, logical_shift)
    return x, y


def decode(pair, affine, width):
    mask = (1 << width) - 1
    return ((pair[0] - pair[1]) & mask) if affine else (pair[0] ^ pair[1])


def additive_to_xor(x, a, r, width, logical_shift=lambda value, amount: value >> amount):
    mask = (1 << width) - 1
    left = (x[0] ^ a, a & mask)
    right = (x[1] ^ r, r & mask)
    xor, inv, *_ = operations(width, logical_shift)
    return add(left, inv(right), width, True, logical_shift)
