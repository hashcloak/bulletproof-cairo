from common_ec_cairo.ec.ec import EcPoint, ec_mul, ec_add
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math_cmp import is_le_felt
from common_ec_cairo.ec.param_def import BASE
from common_ec_cairo.ec.bigint import BigInt3

# Mod x % p using a Python hint and assert the computation in Cairo
func remainder{range_check_ptr}(x: BigInt3, p: BigInt3) -> (r: BigInt3):
    alloc_locals
    local r: BigInt3
    %{
        sys.path.insert(1, './python_bulletproofs')
        sys.path.insert(1, './python_bulletproofs/src')

        from utils.utils import ModP, mod_hash, inner_product, from_cairo_big_int, to_cairo_big_int

        x = from_cairo_big_int(ids.x.d0, ids.x.d1, ids.x.d2)
        p = from_cairo_big_int(ids.p.d0, ids.p.d1, ids.p.d2)
        moded = x % p
        ids.r.d0, ids.r.d1, ids.r.d2 = to_cairo_big_int(moded)
    %}
    
    return (r=r)
end


# TODO: have code that verifies the inverse
func inverse_mod_p(x: BigInt3, p: BigInt3) -> (inv: BigInt3):
    alloc_locals 
    local inv: BigInt3
    %{
        sys.path.insert(1, './python_bulletproofs')
        sys.path.insert(1, './python_bulletproofs/src')
        from utils.utils import ModP, mod_hash, inner_product, from_cairo_big_int, to_cairo_big_int
        x = from_cairo_big_int(ids.x.d0, ids.x.d1, ids.x.d2)
        p = from_cairo_big_int(ids.p.d0, ids.p.d1, ids.p.d2)

        x_modp = ModP(x, p)
        inv = x_modp.inv().x
        ids.inv.d0, ids.inv.d1, ids.inv.d2 = to_cairo_big_int(inv)
    %}


    return (inv = inv)
end

# TODO: check that this is correct
func variable_exponentiaition_felts{range_check_ptr}(x: felt, y: felt) -> (exp: felt):
    alloc_locals 
    local exp: felt
    %{
        ids.exp = pow(ids.x, ids.y, PRIME)
    %}

    return (exp = exp)
end



# Exponentiate x ^ y
# TODO: check that this is correct
func variable_exponentiaition{range_check_ptr}(x: BigInt3, y: BigInt3, p: BigInt3) -> (exp: BigInt3):
    alloc_locals 
    local exp: BigInt3
    %{
        sys.path.insert(1, './python_bulletproofs')
        sys.path.insert(1, './python_bulletproofs/src')
        from utils.utils import ModP, mod_hash, inner_product, from_cairo_big_int, to_cairo_big_int
        x = from_cairo_big_int(ids.x.d0, ids.x.d1, ids.x.d2)
        y = from_cairo_big_int(ids.y.d0, ids.y.d1, ids.y.d2)
        p = from_cairo_big_int(ids.p.d0, ids.p.d1, ids.p.d2)


        exp = pow(x, y, p)
        ids.exp.d0, ids.exp.d1, ids.exp.d2 = to_cairo_big_int(exp)
    %}
    return (exp = exp)
end

func felt_to_bigint(x: felt) -> (bigint: BigInt3):
    alloc_locals
    local bigint3: BigInt3
    %{
        import sys
        sys.path.insert(1, './python_bulletproofs')
        sys.path.insert(1, './python_bulletproofs/src')

        from utils.utils import to_cairo_big_int
        ids.bigint3.d0, ids.bigint3.d1, ids.bigint3.d2 = to_cairo_big_int(ids.x)
    %}
    return (bigint=bigint3)
end

func mult_bigint(x: BigInt3, y: BigInt3, p: BigInt3) -> (z: BigInt3):
    alloc_locals
    local z: BigInt3
    %{
        import sys
        sys.path.insert(1, './python_bulletproofs')
        sys.path.insert(1, './python_bulletproofs/src')

        from utils.utils import to_cairo_big_int, from_cairo_big_int
        x = from_cairo_big_int(ids.x.d0, ids.x.d1, ids.x.d2)
        y = from_cairo_big_int(ids.y.d0, ids.y.d1, ids.y.d2)
        p = from_cairo_big_int(ids.p.d0, ids.p.d1, ids.p.d2)

        ids.z.d0, ids.z.d1, ids.z.d2 = to_cairo_big_int((x * y) % p)
    %}
    return (z = z)
end



# Only works for a small x
# TODO: speedup
# func slow_multiplication_mod_p{range_check_ptr}(x: felt, y: felt, p: felt) -> (output: felt):
#     if x == 1:
#         return (output = y)
#     end
#     let (r) = slow_multiplication_mod_p(x - 1, y, p)
#     let not_modded = r + y
#     let (_, modded) = divide_and_remainder(not_modded, p)
#     return (output = modded)
# end


# TODO: move to a multiexp fn
# TODO: test me by comparing with python...
# g \in G
# and s \in Z
func multi_exp_internal{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}(ss: BigInt3*, n: felt, gs: EcPoint*, i: felt) -> (g: EcPoint):
    alloc_locals
    if i == n - 1:
        let (ec: EcPoint) = ec_mul(gs[i], ss[i])
        return (g=ec)
    end

    let (local ec: EcPoint) = ec_mul(gs[i], ss[i])

    let (recur: EcPoint) = multi_exp_internal(ss, n, gs, i + 1)    
    let (prod: EcPoint) = ec_add(ec, recur)
    
    return (g=prod)
end


func multi_exp{bitwise_ptr : BitwiseBuiltin*, range_check_ptr}(ss: BigInt3*, n: felt, gs: EcPoint*) -> (g: EcPoint):
    %{
        print("QQQQQQQ", ids.n)
    %}
    let (g: EcPoint) = multi_exp_internal(ss, n, gs, 0)
    %{
        print("QQQQQQQ", ids.n)
    %}
    return (g=g)
end

func check_ec_equal(ec1: EcPoint, ec2: EcPoint) -> (success: felt):
  if ec1.x.d0 != ec2.x.d0:
        return (success = 0)
    end
    if ec1.x.d1 != ec2.x.d1:
        return (success = 0)
    end
    if ec1.x.d2 != ec2.x.d2:
        return (success = 0)
    end
    if ec1.y.d0 != ec2.y.d0:
        return (success = 0)
    end
    if ec1.y.d1 != ec2.y.d1:
        return (success = 0)
    end
    if ec1.y.d2 != ec2.y.d2:
        return (success = 0)
    end
    return (success = 1)
end