PROG=	brilter
MAN=
WARNS?=	6

SRCS+=	brilter.c
SRCS+=	netmap.c
SRCS+=	pcap_filter.c
SRCS+=	pipe.c
SRCS+=	script.c

CFLAGS+=-I/usr/local/include/lua52

LDFLAGS+=-L/usr/local/lib

LDADD+=	-llua-5.2
LDADD+=	-lpcap
LDADD+=	-lpthread

DEBUG_FLAGS+=-g

.include <bsd.prog.mk>
