import unittest
import os
from random import randint
from src.pippenger import CURVE

from src.utils.utils import (
    mod_hash,
    point_to_bytes,
)
from src.utils.elliptic_curve_hash import elliptic_hash


class HashTest(unittest.TestCase):
    def test_mod_hash(self):
        p = 1009
        x = mod_hash(b"test", p)
        self.assertLess(x.x, p)
        self.assertEqual(x, mod_hash(b"test", p))
        p = 17
        for _ in range(100):
            msg = os.urandom(10)
            x = mod_hash(msg, p)
            with self.subTest(msg=msg, p=p):
                self.assertNotEqual(x.x, 0)

    def test_elliptic_hash(self):
        for _ in range(100):
            msg = os.urandom(10)
            x = elliptic_hash(msg, CURVE)
            with self.subTest(msg=msg):
                self.assertTrue(CURVE.is_point_on_curve((x.x, x.y)))
