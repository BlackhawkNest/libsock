SHLIB=		sock
SHLIB_MAJOR=	0
MAN=

.PATH:		${.CURDIR}/src
.PATH:		${.CURDIR}/include

INCS+=		libsock.h

SRCS+=		libsock.c

CFLAGS+=	-I${.CURDIR}/include
CFLAGS+=	-I/usr/local/include

LDFLAGS+=	-L/usr/local/lib

LDADD+=		-ltls

.if defined(PREFIX)
LIBDIR=		${PREFIX}/lib
INCLUDEDIR=	${PREFIX}/include
.endif

.include <bsd.lib.mk>
