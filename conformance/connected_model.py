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
