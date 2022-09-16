from fastecdsa.point import Point
from fastecdsa.keys import gen_keypair
from fastecdsa.curve import Curve
from fastecdsa.util import mod_sqrt
from hashlib import sha256, md5

def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(int(a), int((p - 1) / 2), int(p))
    r = -1 if ls == p - 1 else ls
    return r

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.

        0 is returned is no square root exists for
        these a and p.

        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def elliptic_hash(msg: bytes, CURVE: Curve):
    # d, Q = gen_keypair(CURVE)
    # return Q

    prefixed_msg = str(0).encode() + msg
    h = sha256(prefixed_msg).hexdigest()
    x = int(h, 16) % CURVE.p
        
    point = Point(CURVE.gx, CURVE.gy, CURVE) * x
    return point
# Takes in a curve of order ~ 2 ^ 252
# def elliptic_hash(msg: bytes, CURVE: Curve):
#     p = CURVE.p
#     i = 0
#     while True:
#         i += 1
#         prefixed_msg = str(i).encode() + msg
#         h = sha256(prefixed_msg).hexdigest()
#         x = int(h, 16)
#         if x >= p:
#             continue

#         y_sq = (x ** 3 + CURVE.a * x + CURVE.b) % p
#         y = mod_sqrt(y_sq, p)[0]

#         if CURVE.is_point_on_curve((x, y)):
#             b = int(md5(prefixed_msg).hexdigest(), 16) % 2
#             return Point(x, y, CURVE) if b else Point(x, p - y, CURVE)
