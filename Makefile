PROG=	brilter
MAN=
WARNS?=	6

SRCS+=	brilter.c
SRCS+=	netmap.c
SRCS+=	pipe.c

LDADD+=	-lpthread

DEBUG_FLAGS+=-g

.include <bsd.prog.mk>
