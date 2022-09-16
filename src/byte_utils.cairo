from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bitwise import bitwise_and, bitwise_not
from starkware.cairo.common.math_cmp import is_le_felt

// Wrapper function to return n*8 32-bit-words, little endian words representing the input felts
func felts_to_32_bit_word{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(input: felt*, n: felt) -> (
    output: felt*
) {
    let (ptr) = alloc();
    let (ptr) = _felts_to_32_bit_word(input, n, 0, ptr);
    return (output=ptr);
}

func _felts_to_32_bit_word{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    input: felt*, n: felt, i: felt, output: felt*
) -> (output: felt*) {
    if (i == n) {
        return (output=output);
    }

    let (output) = _felt_to_32_bit_word([input + i], output + 8 * i, 0);
    let (output) = _felts_to_32_bit_word(input, n, i + 1, output - 8 * i);
    return (output=output);
}

// Wrapper function to return 8 32-bit-words, little endian, representing the input felt
func felt_to_32_bit_word{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(input: felt) -> (
    output: felt*
) {
    let (ptr) = alloc();

    let (ptr) = _felt_to_32_bit_word(input, ptr, 0);
    return (output=ptr);
}

// Returns 8-32-bit words, little endian, representing the input felt when i = 0
func _felt_to_32_bit_word{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    input: felt, output: felt*, i: felt
) -> (output: felt*) {
    alloc_locals;
    if (i == 8) {
        return (output=output);
    }

    let (anded) = bitwise_and{bitwise_ptr=bitwise_ptr}(input, 2 ** 32 - 1);
    assert [output + i] = anded;
    local lt = is_le_felt{range_check_ptr=range_check_ptr}(2 ** 32, input);
    if (lt == 1) {
        let (mask) = bitwise_not(2 ** 32 - 1);
        let (masked) = bitwise_and(mask, input);
        let new_input = masked / 2 ** 32;
        let (output) = _felt_to_32_bit_word{
            bitwise_ptr=bitwise_ptr, range_check_ptr=range_check_ptr
        }(new_input, output, i + 1);
        return (output=output);
    } else {
        let (output) = _felt_to_32_bit_word(0, output, i + 1);
        return (output=output);
    }
}
