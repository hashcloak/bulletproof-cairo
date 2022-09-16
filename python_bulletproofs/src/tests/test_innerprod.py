import unittest
import os
from random import randint
from fastecdsa.curve import Curve
from src.pippenger import CURVE

from src.group import EC
from src.innerproduct.inner_product_prover import NIProver, FastNIProver2
from src.innerproduct.inner_product_verifier import SUPERCURVE, Verifier1, Verifier2
from src.utils.commitments import vector_commitment
from src.utils.utils import ModP, mod_hash, inner_product
from src.utils.elliptic_curve_hash import elliptic_hash


# python3 -m unittest -v src.tests.test_innerprod.Protocol2Test.test_protocol_2
class Protocol2Test(unittest.TestCase):
    def test_protocol_2(self):
        i_range = [1]
        for i in i_range:
            # seeds = [os.urandom(10) for _ in range(6)]
            seeds = [b"a" for _ in range(6)] # Keep consistent seeds for debugging
            p = SUPERCURVE.q#2 ** 251 + 17 * 2 ** 192 + 1
            N = 2 ** i
            g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
            h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
            u = elliptic_hash(seeds[2], CURVE)
            a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
            b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
            P = vector_commitment(g, h, a, b) + inner_product(a, b) * u

            Prov = FastNIProver2(g, h, u, P, a, b, CURVE, prime=p)
            proof = Prov.prove()
            Verif = Verifier2(g, h, u, P, proof, prime=p)
            with self.subTest(seeds=seeds, N=N):
                self.assertTrue(Verif.verify())

    def test_prover_cheating_false_P_protocol2(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b) + inner_product(a, b) * u
        Prov = FastNIProver2(g, h, u, P, a, b, CURVE)
        proof = Prov.prove()
        Verif = Verifier2(g, h, u, 2 * P, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_a_protocol2(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b) + inner_product(a, b) * u
        a[randint(0, N - 1)] *= 2
        Prov = FastNIProver2(g, h, u, P, a, b, CURVE)
        proof = Prov.prove()
        Verif = Verifier2(g, h, u, P, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_b_protocol2(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b) + inner_product(a, b) * u
        b[randint(0, N - 1)] *= 2
        Prov = FastNIProver2(g, h, u, P, a, b, CURVE)
        proof = Prov.prove()
        Verif = Verifier2(g, h, u, P, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_u_protocol2(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        b[randint(0, N - 1)] *= 2
        P = vector_commitment(g, h, a, b) + inner_product(a, b) * u
        Prov = FastNIProver2(g, h, u, P, a, b, CURVE)
        proof = Prov.prove()
        Verif = Verifier2(g, h, 2 * u, P, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()


class InnerProductArgumentTest(unittest.TestCase):
    def test_different_seeds_innerprod(self):
        for _ in range(10):
            seeds = [os.urandom(10) for _ in range(6)]
            p = CURVE.q
            N = 16
            g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
            h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
            u = elliptic_hash(seeds[2], CURVE)
            a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
            b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
            P = vector_commitment(g, h, a, b)
            c = inner_product(a, b)
            Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
            proof = Prov.prove()
            Verif = Verifier1(g, h, u, P, c, proof)
            with self.subTest(seeds=seeds):
                self.assertTrue(Verif.verify())

    def test_different_N(self):
        for i in range(9):
            seeds = [os.urandom(10) for _ in range(6)]
            p = CURVE.q
            N = 2 ** i
            g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
            h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
            u = elliptic_hash(seeds[2], CURVE)
            a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
            b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
            P = vector_commitment(g, h, a, b)
            c = inner_product(a, b)
            Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
            proof = Prov.prove()
            Verif = Verifier1(g, h, u, P, c, proof)
            with self.subTest(N=N, seeds=seeds):
                self.assertTrue(Verif.verify())

    def test_prover_cheating_false_c(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, P, c + 1, a, b, CURVE, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_P(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, 2 * P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_a(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        a[randint(0, N - 1)] *= 2
        Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_b(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        b[randint(0, N - 1)] *= 2
        Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_u(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        u *= 2
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, 2 * u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_transcript1(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
        proof = Prov.prove()
        randind = randint(0, len(proof.transcript) - 1)
        proof.transcript = (
            proof.transcript[:randind] + os.urandom(1) + proof.transcript[randind + 1 :]
        )
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_transcript2(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = CURVE.q
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, P, c, a, b, CURVE, seeds[5])
        proof = Prov.prove()
        randind = randint(0, len(proof.proof2.transcript) - 1)
        proof.transcript = (
            proof.proof2.transcript[:randind]
            + os.urandom(1)
            + proof.proof2.transcript[randind + 1 :]
        )
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()
