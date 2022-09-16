%builtins range_check bitwise ec_op
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import EcOpBuiltin
from starkware.cairo.common.cairo_blake2s.blake2s import INSTANCE_SIZE, blake2s, finalize_blake2s
from src.innerproduct.innerproduct_2 import verify_innerproduct_2
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.ec_point import EcPoint
from src.structs import Transcript
from src.structs import TranscriptEntry
from src.structs import ProofInnerproduct2

// Return 1 if the proof is verified, otherwise return 0
func _test_with_i_rounds{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*, blake2s_ptr: felt*
}(i_rounds: felt) {
    alloc_locals;

    local transcript: Transcript*;
    local proof_innerprod_2: ProofInnerproduct2;
    local transcript_entries: TranscriptEntry*;
    local gs: EcPoint*;
    local hs: EcPoint*;
    local u: EcPoint*;
    local P: EcPoint*;

    %{
        import sys
        sys.path.insert(1, './python_bulletproofs')
        sys.path.insert(1, './python_bulletproofs/src')

        import os
        from random import randint
        from fastecdsa.curve import secp256k1, Curve

        from group import EC
        from innerproduct.inner_product_prover import NIProver, FastNIProver2
        from innerproduct.inner_product_verifier import SUPERCURVE, Verifier1, Verifier2
        from utils.commitments import vector_commitment
        from utils.utils import ModP, mod_hash, inner_product, set_ec_points
        from utils.elliptic_curve_hash import elliptic_hash

        # Always have the same seeds for easier test consistancy
        # and debugging
        seeds = [b"a" for _ in range(6)]
        CURVE = SUPERCURVE

        # Have a total of "i" rounds
        # for 2 ** i points
        i = ids.i_rounds


        p = SUPERCURVE.q
        N = 2 ** i
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)

        set_ec_points(ids, segments, memory, "u", [u])

        set_ec_points(ids, segments, memory, "gs", g)
        set_ec_points(ids, segments, memory, "hs", h)
    %}

    // Load the vector commitments and proof
    %{
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b) + inner_product(a, b) * u
        set_ec_points(ids, segments, memory, "P", [P])
    %}

    %{
        # Create and set the proof
        Prov = FastNIProver2(g, h, u, P, a, b, CURVE, prime=p)
        proof = Prov.prove() 
        # Convert the proof into a cairo format
        proof.convert_to_cairo(ids, memory, segments, len(g))

        Verif = Verifier2(g, h, u, P, proof, prime=p)
        # For print out purposes
        Verif.verify()
    %}

    let (res: felt) = verify_innerproduct_2(gs, hs, u[0], P[0], proof_innerprod_2, transcript);
    assert res = 1;

    return ();
}

func main{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*}() {
    alloc_locals;
    let (local blake2s_ptr_start) = alloc();
    let blake2s_ptr = blake2s_ptr_start;

    _test_with_i_rounds{blake2s_ptr=blake2s_ptr}(0);
    _test_with_i_rounds{blake2s_ptr=blake2s_ptr}(1);
    _test_with_i_rounds{blake2s_ptr=blake2s_ptr}(2);
    _test_with_i_rounds{blake2s_ptr=blake2s_ptr}(3);
    _test_with_i_rounds{blake2s_ptr=blake2s_ptr}(4);
    _test_with_i_rounds{blake2s_ptr=blake2s_ptr}(5);

    finalize_blake2s(blake2s_ptr_start=blake2s_ptr_start, blake2s_ptr_end=blake2s_ptr);
    return ();
}
