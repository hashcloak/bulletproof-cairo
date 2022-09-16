%builtins output range_check bitwise ec_op 

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import EcOpBuiltin
from starkware.cairo.common.cairo_blake2s.blake2s import INSTANCE_SIZE, blake2s, finalize_blake2s
from src.innerproduct.innerproduct_2 import verify_innerproduct_2
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.ec_point import EcPoint
from src.structs import Transcript
from src.structs import TranscriptEntry
from src.structs import ProofInnerproduct2
from starkware.cairo.common.ec import assert_on_curve, ec_add, ec_double, ec_op
from starkware.cairo.common.serialize import serialize_word

// BASE_POINT is the generator point used in the ECDSA scheme
// https://docs.starkware.co/starkex-v4/crypto/stark-curve

// To generate BASE_BLINDING_POINT, a cryptographic random number is generated
// BASE_BLINDING_POINT is the result of elliptic curve scalar multiplication of
// "cryptographic number" and "BASE_POINT", which the operation is done as offline

// Note that the generated number is less than the order of the starkcurve:
// 3618502788666131213697322783095070105526743751716087489154079457884512865583
// The order of the elliptic curve is found thanks to:
// https://crypto.stackexchange.com/questions/95666/how-to-find-out-what-the-order-of-the-base-point-of-the-elliptic-curve-is

// MINUS_1 is calculated by subtracting -1 from the order of STARKCURVE

const BASE_POINT_X = 874739451078007766457464989774322083649278607533249481151382481072868806602;
const BASE_POINT_Y = 152666792071518830868575557812948353041420400780739481342941381225525861407;
const BASE_BLINDING_POINT_X = 1644404348220522245795652770711644747389835183387584438047505930708711545294;
const BASE_BLINDING_POINT_Y = 3418409665108082357574218324957319851728951500117497918120788963183493908527;
const MINUS_1 = 3618502788666131213697322783095070105526743751716087489154079457884512865582;

func ec_mul{ec_op_ptr: EcOpBuiltin*}(p: EcPoint, m: felt) -> (product: EcPoint) {
    alloc_locals;
    local id_point: EcPoint = EcPoint(0, 0);
    let (r: EcPoint) = ec_op(id_point, m, p);
    return (product=r);
}

func test_blake{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*, blake2s_ptr: felt*
}(){
    alloc_locals;

    let (local transcript: Transcript*) = alloc();
    local proof_innerprod_2: ProofInnerproduct2;
    local transcript_entries: TranscriptEntry*;
    //local gs: EcPoint*;
    //local hs: EcPoint*;
    let (local gs: EcPoint*) = alloc();
    let (local hs: EcPoint*) = alloc();

    local BASE_POINT: EcPoint = EcPoint(BASE_POINT_X, BASE_POINT_Y);
    local BASE_BLINDING_POINT: EcPoint = EcPoint(BASE_BLINDING_POINT_X, BASE_BLINDING_POINT_Y);

    local u: EcPoint = EcPoint(BASE_POINT_X, BASE_POINT_Y);
    local P: EcPoint = EcPoint(BASE_BLINDING_POINT_X, BASE_BLINDING_POINT_Y);

    let (gs1) = ec_mul(BASE_POINT, 2);
    let (gs2) = ec_mul(gs1, 3);
    let (hs1) = ec_mul(gs2, 7);
    let (hs2) = ec_mul(hs1, 4);
    let (u) = ec_mul(hs1, 234);
    let (P) = ec_mul(u, 3485);
    
    assert gs.x = gs1.x;
    assert gs.y = gs1.y;    
    assert gs[1].x = gs2.x;
    assert gs[1].y = gs2.y;

    assert hs.x = hs1.x;
    assert hs.y = hs1.y;    
    assert hs[1].x = hs2.x;
    assert hs[1].y = hs2.y;

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

        seeds = [b"a" for _ in range(6)]
        CURVE = SUPERCURVE

        p = SUPERCURVE.q
        N = 2 ** 1
        g = 1234
        h = 345
        u = 3542
    %}

    // Load the vector commitments and proof
    %{
        a = 8
        b = 3
        P = 12
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

    proof_innerprod_2.a = 1;
    proof_innerprod_2.b = 234;
    proof_innerprod_2.n = 1;

    assert transcript.n_rounds = 1;
    assert transcript.transcript_seed = 4;
    assert transcript.transcript_entries = 4; 

    let (res: felt) = verify_innerproduct_2(gs, hs, u, P, proof_innerprod_2, transcript);
    assert res = 1;

    return();
}


func main{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*}() {
    alloc_locals;
    let (local blake2s_ptr_start) = alloc();
    let blake2s_ptr = blake2s_ptr_start;





    test_blake{blake2s_ptr=blake2s_ptr}();

    finalize_blake2s(blake2s_ptr_start=blake2s_ptr_start, blake2s_ptr_end=blake2s_ptr);

    return ();
}
