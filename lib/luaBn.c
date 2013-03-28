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

#define checkbn(L, narg) ((struct BN *)luaL_checkudata(L, (narg), BN_METATABLE))
#define checkbignum(L, narg) (&checkbn(L, narg)->bignum)

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

//static char ctx_key;

#if LUABN_UINT_MAX > ULONG_MAX
/* Modulo val is used to negate values in numbertobignum(). */
static char modulo_key;
#endif

/* Return luaL_testudata(L, narg, BN_METATABLE). */
static BIGNUM *
testbignum(lua_State *L, int narg)
{
	struct BN *udata;

	/* XXX Use luaL_testudata(L, narg, BN_METATABLE) from 5.2. */
	udata = (struct BN *)lua_touserdata(L, narg);

	if (udata != NULL && lua_getmetatable(L, narg)) {
		lua_getfield(L, LUA_REGISTRYINDEX, BN_METATABLE);
		if (!lua_rawequal(L, -1, -2))
			udata = NULL;
		lua_pop(L, 2);
	}

	return (udata != NULL) ? &udata->bignum : NULL;
}

static inline int
abs_index(lua_State *L, int narg)
{

	return (narg > 0 || narg <= LUA_REGISTRYINDEX) ?
	    narg : lua_gettop(L) + 1 + narg;
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

	narg = abs_index(L, narg);
	rv = newbignum(L);
	lua_replace(L, narg);

	/* XXX "-0xdeadbeef" */
	z = (s[0] == '0') ? 1 : 0;
	if (s[z] == 'x' || s[z] == 'X')
		rvlen = BN_hex2bn(&rv, s + z + 1);
	else
		rvlen = BN_dec2bn(&rv, s);

	if (rvlen == 0)
		luaL_error(L, "unable to parse " BN_METATABLE);

	return rv;
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
	BN_add_word(bn, 1); /* XXX check return value. */
	lua_settable(L, LUA_REGISTRYINDEX);
}

static BIGNUM *
get_modulo_val(lua_State *L)
{
	struct BN *bn;

	lua_pushlightuserdata(L, &modulo_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
	assert(checkbignum(L, -1) != NULL);
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

	narg = abs_index(L, narg);
	rv = newbignum(L);
	lua_replace(L, narg);

	/* 
	 * XXX Check return values of BN_zero, BN_set_word,
	 * BN_lshift, BN_add_word, BN_sub_word and BN_sub.
	 */
	BN_zero(rv);
	for (i = nwords; i > 0; i--) {
		shift = wshift * (i - 1);
		w = (n >> shift) & wmask;
		if (!BN_is_zero(rv)) {
			BN_lshift(rv, rv, wshift);
			BN_add_word(rv, w);
		} else if (w != 0) {
			BN_set_word(rv, w);
		}
	}

	if (d < 0) {
#if LUABN_UINT_MAX < ULONG_MAX
		BN_sub_word(rv, LUABN_UINT_MAX + 1ul);
#elif LUABN_UINT_MAX == ULONG_MAX
		BN_sub_word(rv, 1);
		BN_sub_word(rv, LUABN_UINT_MAX);
#else
		BN_sub(rv, rv, get_modulo_val(L));
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
l_add(lua_State *L)
{
	BIGNUM *o[2];
	BIGNUM *r;
	lua_Number d;
	int narg;

	if ((o[0] = testbignum(L, 1)) == NULL) {
		narg = 1;
		o[1] = luaBn_tobignum(L, 2);
	} else if ((o[1] = testbignum(L, 2)) == NULL) {
		narg = 2;
	} else {
		narg = 0;
	}

	/* XXX Check BN_copy, BN_add and BN_add_word return values. */
	/* XXX what is faster, BN_copy+BN_add_word or BN_init+BN_???+BN_add? */
	if (narg == 0) {
		r = newbignum(L);
		BN_add(r, o[0], o[1]);
	} else {
		d = lua_tonumber(L, narg);
		if (d > 0 && d == (BN_ULONG)d) {
			r = newbignum(L);
			BN_copy(r, o[2-narg]);
			BN_add_word(r, (BN_ULONG)d);
		} else {
			r = o[narg-1] = luaBn_tobignum(L, narg);
			lua_pushvalue(L, narg);
			BN_add(r, o[0], o[1]);
		}
	}

	return 1;
}

static int
l_gc(lua_State *L)
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

static luaL_reg bn_methods[] = {
	{ "tostring", l_tostring },
	{ NULL, NULL}
};

static luaL_reg bn_metafunctions[] = {
	{ "__gc",       l_gc       },
	{ "__add",      l_add      },
	{ "__tostring", l_tostring },
	{ NULL, NULL}
};

static luaL_reg bn_functions[] = {
	{ "number", l_number },
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

int luaBn_open(lua_State *L)
{

	register_udata(L, BN_METATABLE, bn_metafunctions, bn_methods);

	/* XXX luaL_register is deprecated in version 5.2. */
	luaL_register(L, "bn", bn_functions);

#if LUABN_UINT_MAX > ULONG_MAX
	init_modulo_val(L);
#endif

	return 1;
}
