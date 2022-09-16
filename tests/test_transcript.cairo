%builtins output range_check
from src.structs import Transcript, TranscriptEntry

func main{output_ptr: felt*, range_check_ptr: felt}() {
    alloc_locals;
    local transcript: Transcript*;
    %{
        import sys
        sys.path.insert(1, './python_bulletproofs')
        sys.path.insert(1, './python_bulletproofs/src')

        from utils.transcript import Transcript
        from utils.elliptic_curve_hash import elliptic_hash
        from utils.utils import ModP, mod_hash, inner_product
        from fastecdsa.curve import secp256k1, Curve

        CURVE: Curve = secp256k1
        L1 = elliptic_hash(str("AAAA").encode(), CURVE)
        R1 = elliptic_hash(str("BBBB").encode(), CURVE)
        x = ModP(69, 100)


        transcript = Transcript(11)

        transcript.add_point(L1)
        transcript.add_point(R1)
        transcript.add_number(x)

        x2 = ModP(42, 100)
        transcript.add_point(L1)
        transcript.add_point(R1)
        transcript.add_number(x2)

        Transcript.convert_to_cairo(ids, memory, segments, transcript.digest)
    %}
    local transcript_entries: TranscriptEntry* = cast(transcript + 2, TranscriptEntry*);
    assert transcript_entries[0].x = 69;
    assert transcript_entries[1].x = 42;
    assert transcript.transcript_seed = 11;
    assert transcript.n_rounds = 2;
    return ();
}
