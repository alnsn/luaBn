/*-
 * Copyright (c) 2013 Alexander Nasonov.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "luaBn.h"

#include <lua.h>
#include <lauxlib.h>

#include <openssl/bn.h>
#include <openssl/err.h>

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#define BN_METATABLE "bn.number"
#define CTX_METATABLE "bn.ctx"

#define getbn(L, narg) ((struct BN *)lua_touserdata(L, (narg)))
#define checkbn(L, narg) ((struct BN *)luaL_checkudata(L, (narg), BN_METATABLE))
#define checkbignum(L, narg) (&checkbn(L, narg)->bignum)

#define negatebignum(bn) BN_set_negative((bn), !BN_is_negative((bn)))

#ifdef LUA_NUMBER_DOUBLE

typedef int64_t  luaBn_Int;
typedef uint64_t luaBn_UInt;

#define LUABN_UINT_MAX UINT64_MAX

#elif LUA_NUMBER_FLOAT

typedef int32_t  luaBn_Int;
typedef uint32_t luaBn_UInt;

#define LUABN_UINT_MAX UINT32_MAX

#else /* lua_Number is an integral type. */

typedef intmax_t  luaBn_Int;
typedef uintmax_t luaBn_UInt;

#define LUABN_UINT_MAX UINTMAX_MAX

#endif

struct BN
{
	BIGNUM bignum;

	/*
	 * Used to prevent a leak if lua_pushstring() fails to push a string.
	 * Should be freed with OPENSSL_free() and reset to NULL immediately
	 * after the string is successfully pushed.
	 */
	char *str;
};

/*
 * Unique keys to access values in the Lua registry.
 */
static char ctx_key;

#if LUABN_UINT_MAX > ULONG_MAX
/* Modulo val is used to negate values in numbertobignum(). */
static char modulo_key;
#endif

/* 
 * Aka luaL_testudata(L, narg, BN_METATABLE) but it also casts
 * from struct BN to BIGNUM.
 */
static BIGNUM *
testbignum(lua_State *L, int narg)
{
	struct BN *udata;

	udata = getbn(L, narg);

	if (udata != NULL && lua_getmetatable(L, narg)) {
		lua_getfield(L, LUA_REGISTRYINDEX, BN_METATABLE);
		if (!lua_rawequal(L, -1, -2))
			udata = NULL;
		lua_pop(L, 2);
	}

	return (udata != NULL) ? &udata->bignum : NULL;
}

/*
 * Converts absolute or relative stack index to absolute index.
 */
static inline int
absindex(lua_State *L, int narg)
{

	return (narg > 0 || narg <= LUA_REGISTRYINDEX) ?
	    narg : lua_gettop(L) + 1 + narg;
}

/*
 * If abs(d) can be converted BN_ULONG, returns abs(d). Otherwise, returns 0.
 */
static inline BN_ULONG
absnumber(lua_Number d)
{

	if (d > 0 && d == (BN_ULONG)d)
		return (BN_ULONG)d;
	else if (-d > 0 && -d == (BN_ULONG)-d)
		return (BN_ULONG)-d;
	else
		return 0;
}

static int
bnerror(lua_State *L, const char *msg)
{
	const char *s;
	unsigned long e;

	e = ERR_get_error();
	s = ERR_reason_error_string(e);

	if (s != NULL)
		return luaL_error(L, "%s: %s", msg, s);
	else if (e != 0)
		return luaL_error(L, "%s: strings not loaded, code %d", msg, e);
	else
		return luaL_error(L, "%s", msg);
}

/*
 * Creates a new BN object and pushes it to stack.
 */
static BIGNUM *
newbignum(lua_State *L)
{
	struct BN *udata;

	udata = (struct BN *)lua_newuserdata(L, sizeof(struct BN));
	udata->str = NULL;
	BN_init(&udata->bignum);

	luaL_getmetatable(L, BN_METATABLE);
	lua_setmetatable(L, -2);

	return &udata->bignum;
}

/* Replaces string at narg with bignum. */
static BIGNUM *
stringtobignum(lua_State *L, int narg)
{
	BIGNUM *rv;
	const char *s;
	size_t z;
	int rvlen;

	s = lua_tostring(L, narg);
	assert(s != NULL);

	narg = absindex(L, narg);
	rv = newbignum(L);
	lua_replace(L, narg);

	/* XXX "-0xdeadbeef" */
	z = (s[0] == '0') ? 1 : 0;
	if (s[z] == 'x' || s[z] == 'X')
		rvlen = BN_hex2bn(&rv, s + z + 1);
	else
		rvlen = BN_dec2bn(&rv, s);

	if (rvlen == 0)
		bnerror(L, "unable to parse " BN_METATABLE);

	return rv;
}

static BN_CTX *
get_ctx_val(lua_State *L)
{
	BN_CTX **udata;

	lua_pushlightuserdata(L, &ctx_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
	assert(luaL_checkudata(L, -1, CTX_METATABLE) != NULL);
	udata = (BN_CTX **)lua_touserdata(L, -1);
	lua_pop(L, 1);

	return *udata;
}

#if LUABN_UINT_MAX > ULONG_MAX
static BIGNUM *
get_modulo_val(lua_State *L)
{
	struct BN *bn;

	lua_pushlightuserdata(L, &modulo_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
	assert(testbignum(L, -1) != NULL);
	bn = (struct BN *)lua_touserdata(L, -1);
	lua_pop(L, 1);

	return &bn->bignum;
}
#endif

/* Replaces number at narg with bignum. */
static BIGNUM *
numbertobignum(lua_State *L, int narg)
{
	BIGNUM *rv;
	lua_Number d;
	luaBn_UInt n, w;
	size_t i;
	int shift;

	const int wshift = 32;
	const unsigned long wmask = 0xffffffffu;
	const size_t nwords = CHAR_BIT * sizeof(luaBn_UInt) / wshift;

	assert(nwords > 0);

	d = lua_tonumber(L, narg);
	n = (luaBn_Int)d;

	narg = absindex(L, narg);
	rv = newbignum(L);
	lua_replace(L, narg);

	if (!BN_zero(rv))
		bnerror(L, "BN_zero in numbertobignum");

	for (i = nwords; i > 0; i--) {
		shift = wshift * (i - 1);
		w = (n >> shift) & wmask;

		if (!BN_is_zero(rv)) {
			if (!BN_lshift(rv, rv, wshift))
				bnerror(L, "BN_lshift in numbertobignum");
			if (!BN_add_word(rv, w))
				bnerror(L, "BN_add_word in numbertobignum");
		} else if (w != 0) {
			if (!BN_set_word(rv, w))
				bnerror(L, "BN_set_word in numbertobignum");
		}
	}

	if (d < 0) {
#if LUABN_UINT_MAX < ULONG_MAX
		if (!BN_sub_word(rv, LUABN_UINT_MAX + 1ul))
			bnerror(L, "BN_sub_word in numbertobignum");
#elif LUABN_UINT_MAX == ULONG_MAX
		if (!BN_sub_word(rv, 1))
			bnerror(L, "BN_sub_word in numbertobignum");
		if (!BN_sub_word(rv, LUABN_UINT_MAX))
			bnerror(L, "BN_sub_word in numbertobignum");
#else
		if (!BN_sub(rv, rv, get_modulo_val(L)))
			bnerror(L, "BN_sub in numbertobignum");
#endif
	}

	return rv;
}

/*
 * Converts an object at index narg to BIGNUM
 * and returns a pointer to that object.
 */
BIGNUM *
luaBn_tobignum(lua_State *L, int narg)
{

	switch (lua_type(L, narg)) {
		case LUA_TNUMBER:   return numbertobignum(L, narg);
		case LUA_TSTRING:   return stringtobignum(L, narg);
		case LUA_TUSERDATA: return checkbignum(L, narg);
	}

	luaL_typerror(L, narg, "number, string or " BN_METATABLE);
	return NULL;
}

static int
l_number(lua_State *L)
{
	luaBn_tobignum(L, 1);
	lua_pushvalue(L, 1);
	return 1;
}

static int
l_tostring(lua_State *L)
{
	struct BN *bn;

	bn = checkbn(L, 1);

	if (bn->str != NULL)
		OPENSSL_free(bn->str);
	bn->str = BN_bn2dec(&bn->bignum);

	lua_pushstring(L, bn->str);

	OPENSSL_free(bn->str);
	bn->str = NULL;

	return 1;
}

static int
l_unm(lua_State *L)
{
	BIGNUM *o, *r;

	assert(testbignum(L, 1) != NULL);
	o = &getbn(L, 1)->bignum;
	r = newbignum(L);

	if (!BN_copy(r, o))
		return bnerror(L, BN_METATABLE ".__unm");

	negatebignum(r);

	return 1;
}

/* Implementation of l_add and l_sub. */
static inline int
addsub(lua_State *L, int sign, const char *errmsg)
{
	BIGNUM *bn[3]; /* bn[0] = bn[1] +/- bn[2] */
	BN_ULONG n;
	lua_Number d;
	int narg, status;

	if ((bn[2] = testbignum(L, 2)) == NULL) {
		narg = 2;
		assert(testbignum(L, 1) != NULL);
		bn[1] = &getbn(L, 1)->bignum;
	} else if ((bn[1] = testbignum(L, 1)) == NULL) {
		narg = 1;
	} else {
		narg = 0;
	}

	status = 0;

	if (narg == 0) {
		bn[0] = newbignum(L);
		status = sign > 0 ? BN_add(bn[0], bn[1], bn[2])
		                  : BN_sub(bn[0], bn[1], bn[2]);
	} else {
		d = lua_tonumber(L, narg);
		n = absnumber(d);

		if (n == 0) {
			bn[0] = bn[narg] = luaBn_tobignum(L, narg);
			lua_pushvalue(L, narg);
			status = sign > 0 ? BN_add(bn[0], bn[1], bn[2])
			                  : BN_sub(bn[0], bn[1], bn[2]);
		} else {
			bn[0] = newbignum(L);
			if (BN_copy(bn[0], bn[3-narg])) {
				if (sign * d > 0)
					status = BN_add_word(bn[0], n);
				else
					status = BN_sub_word(bn[0], n);
				if (sign * narg == -1)
					negatebignum(bn[0]);
			}
		}
	}

	if (status == 0)
		return bnerror(L, errmsg);

	return 1;
}

static int
l_add(lua_State *L)
{

	return addsub(L, 1, BN_METATABLE ".__add");
}

static int
l_sub(lua_State *L)
{

	return addsub(L, -1, BN_METATABLE ".__sub");
}

static int
l_mul(lua_State *L)
{
	BIGNUM *bn[3]; /* bn[0] = bn[1] * bn[2] */
	BN_CTX *ctx;
	BN_ULONG n;
	lua_Number d;
	int narg, status;

	if ((bn[1] = testbignum(L, 1)) == NULL) {
		narg = 1;
		assert(testbignum(L, 2) != NULL);
		bn[2] = &getbn(L, 2)->bignum;
	} else if ((bn[2] = testbignum(L, 2)) == NULL) {
		narg = 2;
	} else {
		narg = 0;
	}

	status = 0;

	if (narg == 0) {
		bn[0] = newbignum(L);
		ctx = get_ctx_val(L);
		status = BN_mul(bn[0], bn[1], bn[2], ctx);
	} else {
		d = lua_tonumber(L, narg);
		n = absnumber(d);

		if (n == 0) {
			bn[0] = bn[narg] = luaBn_tobignum(L, narg);
			lua_pushvalue(L, narg);
			ctx = get_ctx_val(L);
			status = BN_mul(bn[0], bn[1], bn[2], ctx);
		} else {
			bn[0] = newbignum(L);
			if (BN_copy(bn[0], bn[3-narg])) {
				if (-d > 0)
					negatebignum(bn[0]);
				status = BN_mul_word(bn[0], n);
			}
		}
	}

	if (status == 0)
		return bnerror(L, BN_METATABLE ".__mul");

	return 1;
}

static int
l_div(lua_State *L)
{
	BIGNUM *bn[3]; /* bn[0] = bn[1] / bn[2] */
	BN_CTX *ctx;
	BN_ULONG n, rem;
	lua_Number d;
	int status;

	/*
	 * Unlike many other operations (e.g. BN_add or BN_mul),
	 * documentation for BN_div doesn't specify that the result
	 * may be the same variable as one of the operands.
	 * Thus, always allocate a new BIGNUM object for the result.
	 */
	bn[0] = newbignum(L);

	n = 0;
	status = 0;

	if ((bn[2] = testbignum(L, 2)) != NULL) {
		bn[1] = luaBn_tobignum(L, 1);
	} else {
		assert(testbignum(L, 1) != NULL);
		bn[1] = &getbn(L, 1)->bignum;

		d = lua_tonumber(L, 2);
		n = absnumber(d);

		if (n == 0) {
			bn[2] = luaBn_tobignum(L, 2);
		} else if (BN_copy(bn[0], bn[1])) {
			if (-d > 0)
				negatebignum(bn[0]);
			rem = BN_div_word(bn[0], n);
			/*
			 * Code inspection shows that BN_div_word() doesn't
			 * set error only when n == 0. Therefore, bnerror()
			 * call is valid if BN_div_word() fails.
			 */
			status = (rem != (BN_ULONG)-1);
		}
	}

	if (n == 0) {
		ctx = get_ctx_val(L);
		status = BN_div(bn[0], NULL, bn[1], bn[2], ctx);
	}

	if (status == 0)
		return bnerror(L, BN_METATABLE ".__div");

	return 1;
}

static int
l_mod(lua_State *L)
{
	BIGNUM *bn[3]; /* bn[0] = bn[1] % bn[2] */
	BN_CTX *ctx;
	BN_ULONG n, rem;
	lua_Number d;
	int status;

	/*
	 * Unlike many other operations (e.g. BN_add or BN_mul),
	 * documentation for BN_div doesn't specify that the result
	 * may be the same variable as one of the operands.
	 * Thus, always allocate a new BIGNUM object for the result.
	 */
	bn[0] = newbignum(L);

	n = 0;
	status = 0;

	if ((bn[2] = testbignum(L, 2)) != NULL) {
		bn[1] = luaBn_tobignum(L, 1);
	} else {
		assert(testbignum(L, 1) != NULL);
		bn[1] = &getbn(L, 1)->bignum;

		d = lua_tonumber(L, 2);
		n = absnumber(d);

		if (n == 0) {
			bn[2] = luaBn_tobignum(L, 2);
		} else {
			rem = BN_mod_word(bn[1], n);
			/*
			 * Code inspection shows that BN_mod_word() never
			 * fails for n != 0.
			 */
			assert(rem < n);
			status = BN_set_word(bn[0], rem);
			if (status != 0)
				BN_set_negative(bn[0], BN_is_negative(bn[1]));
		}
	}

	if (n == 0) {
		ctx = get_ctx_val(L);
		status = BN_div(NULL, bn[0], bn[1], bn[2], ctx);
	}

	if (status == 0)
		return bnerror(L, BN_METATABLE ".__mod");

	return 1;
}

static int
l_gcd(lua_State *L)
{
	BIGNUM *bn[3]; /* bn[0] = gcd(bn[1], bn[2]) */
	BN_CTX *ctx;

	assert(testbignum(L, 1) != NULL);
	bn[1] = &getbn(L, 1)->bignum;

	if ((bn[2] = testbignum(L, 2)) != NULL) {
		bn[0] = newbignum(L);
	} else {
		bn[0] = bn[2] = luaBn_tobignum(L, 2);
		lua_pushvalue(L, 2);
	}

	ctx = get_ctx_val(L);

	if (!BN_gcd(bn[0], bn[1], bn[2], ctx))
		return bnerror(L, BN_METATABLE ".gcd");

	return 1;
}

static int
l_modadd(lua_State *L)
{
	BIGNUM *mod;
	BIGNUM *bn[3]; /* bn[0] = bn[1] + bn[2] modulo mod */
	BN_CTX *ctx;

	bn[0] = newbignum(L);

	assert(testbignum(L, 1) != NULL);
	bn[1] = &getbn(L, 1)->bignum;

	bn[2] = luaBn_tobignum(L, 2);
	mod   = luaBn_tobignum(L, 3);

	ctx = get_ctx_val(L);

	if (!BN_mod_add(bn[0], bn[1], bn[2], mod, ctx))
		return bnerror(L, BN_METATABLE ".modadd");

	return 1;
}

static int
l_modsub(lua_State *L)
{
	BIGNUM *mod;
	BIGNUM *bn[3]; /* bn[0] = bn[1] - bn[2] modulo mod */
	BN_CTX *ctx;

	bn[0] = newbignum(L);

	assert(testbignum(L, 1) != NULL);
	bn[1] = &getbn(L, 1)->bignum;

	bn[2] = luaBn_tobignum(L, 2);
	mod   = luaBn_tobignum(L, 3);

	ctx = get_ctx_val(L);

	if (!BN_mod_sub(bn[0], bn[1], bn[2], mod, ctx))
		return bnerror(L, BN_METATABLE ".modsub");

	return 1;
}

static int
l_modmul(lua_State *L)
{
	BIGNUM *mod;
	BIGNUM *bn[3]; /* bn[0] = bn[1] * bn[2] modulo mod */
	BN_CTX *ctx;

	assert(testbignum(L, 1) != NULL);
	bn[1] = &getbn(L, 1)->bignum;

	if ((bn[2] = testbignum(L, 2)) != NULL) {
		bn[0] = newbignum(L);
	} else {
		bn[0] = bn[2] = luaBn_tobignum(L, 2);
		lua_pushvalue(L, 2);
	}

	mod = luaBn_tobignum(L, 3);

	ctx = get_ctx_val(L);

	if (!BN_mod_mul(bn[0], bn[1], bn[2], mod, ctx))
		return bnerror(L, BN_METATABLE ".modmul");

	return 1;
}

static int
l_modpow(lua_State *L)
{
	BIGNUM *mod;
	BIGNUM *bn[3]; /* bn[0] = bn[1] ^ bn[2] modulo mod */
	BN_CTX *ctx;

	bn[0] = newbignum(L);

	assert(testbignum(L, 1) != NULL);
	bn[1] = &getbn(L, 1)->bignum;

	bn[2] = luaBn_tobignum(L, 2);
	mod   = luaBn_tobignum(L, 3);

	ctx = get_ctx_val(L);

	if (!BN_mod_exp(bn[0], bn[1], bn[2], mod, ctx))
		return bnerror(L, BN_METATABLE ".modpow");

	return 1;
}

static int
l_modsqr(lua_State *L)
{
	BIGNUM *mod;
	BIGNUM *bn[2]; /* bn[0] = sqr(bn[1]) modulo mod */
	BN_CTX *ctx;

	bn[0] = newbignum(L);

	assert(testbignum(L, 1) != NULL);
	bn[1] = &getbn(L, 1)->bignum;

	mod = luaBn_tobignum(L, 2);

	ctx = get_ctx_val(L);

	if (!BN_mod_sqr(bn[0], bn[1], mod, ctx))
		return bnerror(L, BN_METATABLE ".modsqr");

	return 1;
}

static int
l_pow(lua_State *L)
{
	BIGNUM *bn[3]; /* bn[0] = bn[1] ^ bn[2] */
	BN_CTX *ctx;

	/*
	 * BN_exp doesn't specify that the result may be the same variable
	 * as one of the operands and there is no BN_exp_word.
	 * These two facts don't leave any room for optimization.
	 */
	bn[0] = newbignum(L);
	bn[1] = luaBn_tobignum(L, 1);
	bn[2] = luaBn_tobignum(L, 2);

	ctx = get_ctx_val(L);

	if (!BN_exp(bn[0], bn[1], bn[2], ctx))
		return bnerror(L, BN_METATABLE ".pow");

	return 1;
}

static int
l_sqr(lua_State *L)
{
	BIGNUM *r, *bn;
	BN_CTX *ctx;

	assert(testbignum(L, 1) != NULL);
	bn = &getbn(L, 1)->bignum;

	r = newbignum(L);
	ctx = get_ctx_val(L);

	if (!BN_sqr(r, bn, ctx))
		return bnerror(L, BN_METATABLE ".sqr");

	return 1;
}

static int
gcbn(lua_State *L)
{
	struct BN *udata;

	udata = checkbn(L, 1);

	BN_free(&udata->bignum);
	if (udata->str != NULL)
		OPENSSL_free(udata->str);

	lua_pushnil(L);
	lua_setmetatable(L, 1);

	return 0;
}

static int
gcctx(lua_State *L)
{
	BN_CTX **udata;

	udata = (BN_CTX **)luaL_checkudata(L, 1, CTX_METATABLE);

	if (*udata != NULL)
		BN_CTX_free(*udata);

	lua_pushnil(L);
	lua_setmetatable(L, 1);

	return 0;
}

static luaL_reg bn_methods[] = {
	{ "gcd",      l_gcd      },
	{ "modadd",   l_modadd   },
	{ "modsub",   l_modsub   },
	{ "modmul",   l_modmul   },
	{ "modpow",   l_modpow   },
	{ "modsqr",   l_modsqr   },
	{ "pow",      l_pow      },
	{ "sqr",      l_sqr      },
	{ "tostring", l_tostring },
	{ NULL, NULL}
};

static luaL_reg bn_metafunctions[] = {
	{ "__gc",       gcbn       },
	{ "__add",      l_add      },
	{ "__div",      l_div      },
	{ "__mod",      l_mod      },
	{ "__mul",      l_mul      },
	{ "__sub",      l_sub      },
	{ "__unm",      l_unm      },
	{ "__tostring", l_tostring },
	{ NULL, NULL}
};

static luaL_reg bn_functions[] = {
	{ "number", l_number },
	{ NULL, NULL}
};

static luaL_reg ctx_metafunctions[] = {
	{ "__gc", gcctx },
	{ NULL, NULL}
};

static int
register_udata(lua_State *L, const char *tname,
    const luaL_reg *metafunctions, const luaL_reg *methods)
{

	luaL_newmetatable(L, tname);

	if (metafunctions != NULL)
		luaL_register(L, NULL, metafunctions);

	if (methods != NULL) {
		/* XXX luaL_register is deprecated in version 5.2. */
		lua_pushstring(L, "__index");
		lua_newtable(L);
		luaL_register(L, NULL, methods);
		lua_rawset(L, -3);
	}

	lua_pop(L, 1);

	return 0;
}

static void
init_ctx_val(lua_State *L)
{
	BN_CTX **udata;

	lua_pushlightuserdata(L, &ctx_key);

	/* Store a pointer to BN_CTX because it's incomplete type. */
	udata = (BN_CTX **)lua_newuserdata(L, sizeof(BN_CTX *));
	*udata = NULL;

	luaL_getmetatable(L, CTX_METATABLE);
	lua_setmetatable(L, -2);

	lua_settable(L, LUA_REGISTRYINDEX);

	*udata = BN_CTX_new();
	if (*udata == NULL)
		bnerror(L, "BN_CTX_new in init_ctx_val");
}

#if LUABN_UINT_MAX > ULONG_MAX
static void
init_modulo_val(lua_State *L)
{
	char buf[64];
	BIGNUM *bn;
	int n;

	n = sprintf(buf,"%ju", (uintmax_t)LUABN_UINT_MAX);
	assert(n > 0 && n < sizeof(buf));

	lua_pushlightuserdata(L, &modulo_key);
	lua_pushlstring(L, buf, n);
	bn = stringtobignum(L, -1);
	if (!BN_add_word(bn, 1))
		bnerror(L, "BN_add_word in init_modulo_val");
	lua_settable(L, LUA_REGISTRYINDEX);
}
#endif

int luaBn_open(lua_State *L)
{

	register_udata(L, BN_METATABLE, bn_metafunctions, bn_methods);
	register_udata(L, CTX_METATABLE, ctx_metafunctions, NULL);

	/* XXX luaL_register is deprecated in version 5.2. */
	luaL_register(L, "bn", bn_functions);

	init_ctx_val(L);

#if LUABN_UINT_MAX > ULONG_MAX
	init_modulo_val(L);
#endif

	return 1;
}
