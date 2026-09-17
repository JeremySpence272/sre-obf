"""Bit-precise reference for connected XOR transfers, not a compiler proof."""

def operations(width):
    mask = (1 << width) - 1
    def xor(x, y): return (x[0] ^ y[0], x[1] ^ y[1])
    def inv(x): return (x[0] ^ mask, x[1])
    def rotate(x):
        if width == 1: return x
        d = 1 + 3 % (width - 1)
        return ((x << d) | (x >> (width-d))) & mask
    def land(x, y):
        r = x[1] ^ rotate(y[1])
        e = (x[0] & y[0]) ^ (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[1] & y[1])
        return (e ^ r, r)
    def lor(x, y): return xor(xor(x, y), land(x, y))
    def shl(x, d): return ((x[0] << d) & mask, (x[1] << d) & mask)
    def lshr(x, d): return (x[0] >> d, x[1] >> d)
    return xor, inv, land, lor, shl, lshr


def compare(x, y, width, signed=False, equality=False):
    xor, inv, land, lor, shl, lshr = operations(width)
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
