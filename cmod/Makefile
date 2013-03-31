LUA_CMODULE=	bn
SRCS=		bn.c

PKG_CONFIG_DEPS+=	lua
PKG_CONFIG_DEPS+=	openssl

LDCOMPILER=	yes

WARNS=	4

COPTS+=		-O2 -g
CPPFLAGS+=	-I ../lib

LDADD+=		-lluaBn -lcrypto
LDFLAGS+=	-L ${.OBJDIR}/../lib

.include <mkc.lib.mk>
