LIB=	luaBn
SRCS=	luaBn.c

PKG_CONFIG_DEPS+=	lua
PKG_CONFIG_DEPS+=	openssl

SHLIB_MAJOR=	1
SHLIB_MINOR=	0
SHLIB_TEENY=	0

LDCOMPILER=	yes

WARNS=	4

COPTS+=		-O2 -g

LDADD+=		-lcrypto

.include <mkc.lib.mk>
