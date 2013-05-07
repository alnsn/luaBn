luaBn
=====

Lua binding for openssl bn library

C API
=====

    #include <luaBn.h>

    -lluaBn -lcrypto

    int luaBn_open(lua_State \*L);

    BIGNUM \*luaBn_tobignum(lua_State \*L, int narg);

Lua API
=======

     local bn = require "bn"

     -- For notation purposes

     local n, s, b, a = ... -- Lua "number", "string", "bn.number" type and any of these type

     bn.number(n), bn.number(s) - create bignum object from Lua number or string

     b:tostring(), b:__tostring() - convert bignum to string

     bn.isneg(a), b:isneg() - check whether bignum value is negative

     bn.isodd(a), b:isodd() - check whether bignum value is odd

     bn.iseven(a), b:iseven() - check whether bignum value is even

     bn.isone(a), b:isone() - check whether bignum value is equal to one

     bn.iszero(a), b:iszero() - check whether bignum value is equal to zero

     bn.cmp(a1, a2), b1:cmp(a2) - compare values with `BN_cmp` and return its value

     bn.ucmp(a1, a2), b1:ucmp(a2) - compare absolute values with `BN_ucmp` and return its value

     bn.swap(b1, b2), b1:swap(b2) - swap values of b1 and b2

     b:add(a), b:sub(a), b:mul(a), b:div(a) - arithmetic operations

     bn.add(a1, a2), bn.sub(a1, a2), bn.mul(a1, a2), bn.div(a1, a2) - arithmetic operations

     b:modadd(a1, a2), b:modsub(a1, a2), b:modmul(a1, a2), b:moddiv(a1, ad2) - arithmetic modulo `a2` operations

     bn.modadd(a1, a2, a3), bn.modsub(a1, a2, a3), bn.modmul(a1, a2, a3), bn.moddiv(a1, a2, a3) - arithmetic modulo `a3` operations

