from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import EcOpBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from src.structs import Transcript, TranscriptEntry, ProofInnerproduct2
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import ec_add
from src.math_utils import multi_exp, check_ec_equal, ec_mul
from src.q_field import inv_mod_Q, mul_mod_Q
from src.hash import blake2s_hash_felts
from starkware.cairo.common.pow import pow
from starkware.cairo.common.bitwise import bitwise_and

// Return a 1 if the transcript was successfully verified
// Here we just check that all the x values are determined by the hash of the prior values in the transcript
func verify_transcript_inner_product_2{
    bitwise_ptr: BitwiseBuiltin*, range_check_ptr, blake2s_ptr: felt*
}(transcript: Transcript*, i: felt) -> (success: felt) {
    alloc_locals;
    if (i == transcript.n_rounds) {
        return (success=1);
    }
    let transcript_felts: felt* = cast(transcript, felt*);

    // Offset the length by 1
    // 1 elements for the seed, then 5 for each entry, not including the last hash
    let (hashed: felt) = blake2s_hash_felts(transcript_felts + 1, (i + 1) * 5);
    assert hashed = cast(transcript + 2, TranscriptEntry*)[i].x;

    let (local recur_success: felt) = verify_transcript_inner_product_2(transcript, i + 1);
    return (success=recur_success);
}

// As per the bottom of page 15 of the paper, get the each entry in the s vector
func get_ssi{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    transcript: Transcript*, i: felt, j: felt
) -> (ssi: felt) {
    alloc_locals;

    // log_n and the number of "rounds" are the same
    let log_n = transcript.n_rounds;

    if (j == log_n) {
        let one: felt = 1;
        return (ssi=one);
    }

    // A mask for the jth bit of a number at most 2 ** log_n - 1
    // the mask is just a 1 at the jth position

    // Bits are indexed from their starting position so we have to mask from the
    // left hand side
    let (mask) = pow{range_check_ptr=range_check_ptr}(2, log_n - j - 1);
    let (local b_i_j) = bitwise_and(i, mask);

    let (r) = get_ssi(transcript, i, j + 1);
    if (b_i_j == 0) {
        let (curr_mult: felt) = inv_mod_Q(cast(transcript + 2, TranscriptEntry*)[j].x);
        let (ssi: felt) = mul_mod_Q(r, curr_mult);
        return (ssi=ssi);
    } else {
        let curr_mult = cast(transcript + 2, TranscriptEntry*)[j].x;
        let (ssi: felt) = mul_mod_Q(r, curr_mult);
        return (ssi=ssi);
    }
}

// As per the bottom of page 15 of the paper, get the s vector and its inverse
func get_ss_and_inverse{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    ss: felt*, ssinv: felt*, n: felt, transcript: Transcript*, i: felt
) -> (ss_ret: felt*, ssinv_ret: felt*) {
    if (i == n) {
        return (ss_ret=ss, ssinv_ret=ssinv);
    }
    let (ssi: felt) = get_ssi(transcript, i, 0);
    let (ssi_inv: felt) = inv_mod_Q(ssi);

    assert ss[i] = ssi;
    assert ssinv[i] = ssi_inv;

    let (ss, ssinv) = get_ss_and_inverse(ss, ssinv, n, transcript, i + 1);
    return (ss_ret=ss, ssinv_ret=ssinv);
}

// Get the value to multiply the initial commitment, P, by to get P'
// This follows equation (31) on page 16 of the bulletproof paper
func get_final_P_difference{range_check_ptr, ec_op_ptr: EcOpBuiltin*, bitwise_ptr: BitwiseBuiltin*}(
    transcript: Transcript*, i: felt
) -> (P_diff: EcPoint) {
    alloc_locals;
    let transcript_entries: TranscriptEntry* = cast(transcript + 2, TranscriptEntry*);
    let (x_inv: felt) = inv_mod_Q(transcript_entries[i].x);

    let (curr_add_L_1: EcPoint) = ec_mul(transcript_entries[i].L, transcript_entries[i].x);
    let (curr_add_L: EcPoint) = ec_mul(curr_add_L_1, transcript_entries[i].x);

    let (curr_add_R_1: EcPoint) = ec_mul(transcript_entries[i].R, x_inv);
    let (curr_add_R: EcPoint) = ec_mul(curr_add_R_1, x_inv);
    let (curr_diff: EcPoint) = ec_add(curr_add_L, curr_add_R);

    if (i == transcript.n_rounds - 1) {
        return (P_diff=curr_diff);
    }
    let (recur_diff) = get_final_P_difference(transcript, i + 1);
    let (added_diff) = ec_add(recur_diff, curr_diff);
    return (P_diff=added_diff);
}

// Following page 16 of the Bullet proofs paper
// Return 0 if successful, otherwise return 1
func verify_innerproduct_2{
    range_check_ptr, ec_op_ptr: EcOpBuiltin*, bitwise_ptr: BitwiseBuiltin*, blake2s_ptr: felt*
}(
    gs: EcPoint*,
    hs: EcPoint*,
    u: EcPoint,
    P: EcPoint,
    proof: ProofInnerproduct2,
    transcript: Transcript*,
) -> (success: felt) {
    alloc_locals;

    let (ss: felt*) = alloc();
    let (ssinv: felt*) = alloc();
    let (transcript_verified) = verify_transcript_inner_product_2(transcript, 0);

    // Fail if the transcript is not verified
    if (transcript_verified == 0) {
        return (success=0);
    }

    // Get the s vector and all corresponding inverses (see page 15 of the paper)
    let (local ss, ssinv) = get_ss_and_inverse(ss, ssinv, proof.n, transcript, 0);

    let (g: EcPoint) = multi_exp(ss, proof.n, gs);
    let (h: EcPoint) = multi_exp(ssinv, proof.n, hs);

    let (g_a: EcPoint) = ec_mul(g, proof.a);

    let (h_b: EcPoint) = ec_mul(h, proof.b);

    let (u_a: EcPoint) = ec_mul(u, proof.a);
    let (u_ab: EcPoint) = ec_mul(u_a, proof.b);

    let (LHS_1: EcPoint) = ec_add(g_a, h_b);
    let (LHS: EcPoint) = ec_add(LHS_1, u_ab);

    if (transcript.n_rounds == 0) {
        let (success) = check_ec_equal(LHS, P);
        return (success=success);
    }

    let (P_diff) = get_final_P_difference(transcript, 0);
    let (P_prime) = ec_add(P, P_diff);

    let (success) = check_ec_equal(LHS, P_prime);
    return (success=success);
}
