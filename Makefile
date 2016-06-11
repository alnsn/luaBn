.POSIX:

DSO?=		so  # or dylib
LUAPKG?=	lua # pkg-config name

WARNS?=		-Wall -Wextra
PICFLAGS?=	-fPIC
PICLDFLAGS?=	-fPIC

CPPFLAGS+=	-DNDEBUG
XCFLAGS=	-I. $(CPPFLAGS) $(WARNS)

OBJ=		luaBn.o
LIBNAME=	libluaBn.$(DSO) # XXX major.minor.teeny
CMODNAME=	bn.$(DSO) # XXX ln 

.SUFFIXES: .c .o

.c.o:
	$(CC) `pkg-config --cflags $(LUAPKG)` $(XCFLAGS) $(PICFLAGS) $(CFLAGS) -c $< -o $@

all: $(LIBNAME)

$(LIBNAME): $(OBJ)
	$(CC)  `pkg-config --cflags --libs $(LUAPKG)` $(PICLDFLAGS) $(LDFLAGS) -shared $(OBJ) -o $@

clean:
	rm -f $(OBJ) $(LIBNAME)
