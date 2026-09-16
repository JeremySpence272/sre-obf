"""Exact modular specification and known-representation recovery control."""


def encode(x, mask, a, b, width):
    return (a * x + b * mask) % (1 << width)


def recover(encoded, mask, a, b, width):
    return ((encoded - b * mask) * pow(a, -1, 1 << width)) % (1 << width)


def transfer(op, ex, rx, ey, ry, mask, a, b, width, shift=0):
    modulus = 1 << width
    if op == "add":
        return (ex + ey + b * (mask - rx - ry)) % modulus
    if op == "sub":
        return (ex - ey + b * (mask - rx + ry)) % modulus
    if op == "shl":
        return ((ex << shift) + b * (mask - (rx << shift))) % modulus
    if op == "mul":
        product = ex * ey - b * (ex * ry + ey * rx) + b * b * rx * ry
        return (pow(a, -1, modulus) * product + b * mask) % modulus
    raise ValueError(op)
