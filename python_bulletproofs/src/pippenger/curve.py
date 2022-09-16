from fastecdsa.curve import secp256k1, Curve
from fastecdsa.point import Point

# Thanks to https://crypto.stackexchange.com/questions/95666/how-to-find-out-what-the-order-of-the-base-point-of-the-elliptic-curve-is
# for providing the order of the base point
# Note that Q < p
Q = 3618502788666131213697322783095070105526743751716087489154079457884512865583

p = 3618502788666131213697322783095070105623107215331596699973092056135872020481
a = 1
b = 3141592653589793238462643383279502884197169399375105820974944592307816406665
gx = 874739451078007766457464989774322083649278607533249481151382481072868806602
gy = 152666792071518830868575557812948353041420400780739481342941381225525861407

_STARKCURVE = Curve("Starknet curve", p,
                    1,
                    b,
                    Q,
                    gx,
                    gy)

p = Point(gx,gy, _STARKCURVE)


CURVE = _STARKCURVE
