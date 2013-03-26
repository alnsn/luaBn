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
#include <stdbool.h>

#define BN_METATABLE "bn.number"

#define checkbn(L, narg) ((struct BN *)luaL_checkudata(L, (narg), BN_METATABLE))
#define checkbignum(L, narg) (&checkbn(L, narg)->bignum)

struct BN
{
	BIGNUM bignum;

	/*
	 * Used to prevent a leak if lua_pushstring() fails.
	 * Should be freed with OPENSSL_free() immediately after
	 * a string is successfully pushed.
	 */
	char *str;
};

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

/*
 * Converts an object at index narg to BIGNUM
 * and returns a pointer to that object.
 */
BIGNUM *
luaBn_tobignum(lua_State *L, int narg)
{
	BIGNUM *bn;
	const char *s;
	size_t z;
	int len;
#ifdef LUA_NUMBER_DOUBLE
	lua_Number d;
	int64_t n;
#endif

	switch (lua_type(L, narg)) {
		case LUA_TNUMBER:
#ifdef LUA_NUMBER_DOUBLE
			d = lua_tonumber(L, narg);

			n = d;
			if (n < 0)
				n = -n;
			assert(n >= 0);

			narg = abs_index(L, narg);
			bn = newbignum(L);

			/* 
			 * XXX Check return values of BN_set_word,
			 * BN_lshift and BN_add_word.
			 */
			BN_set_word(bn, n & 0xffffffff);
			n >>= 32;

			if (n != 0) {
				BN_lshift(bn, bn, 32);
				BN_add_word(bn, n);
			}

			BN_set_negative(bn, d < 0);

			lua_replace(L, narg);

			return bn;
#else
			/* XXX Don't convert number to string. */
#endif
		case LUA_TSTRING:
			narg = abs_index(L, narg);
			s = lua_tostring(L, narg);
			assert(s != NULL);

			bn = newbignum(L);

			/* XXX "-0xdeadbeef" */
			z = (s[0] == '0') ? 1 : 0;
			if (s[z] == 'x' || s[z] == 'X')
				len = BN_hex2bn(&bn, s + z + 1);
			else
				len = BN_dec2bn(&bn, s);

			if (len == 0)
				luaL_error(L, "unable to parse " BN_METATABLE);

			lua_replace(L, narg);

			return bn;

		case LUA_TUSERDATA:
			return checkbignum(L, narg);
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

	return 1;
}
