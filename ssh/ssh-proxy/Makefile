#	$OpenBSD: Makefile,v 1.24 2010/02/09 08:55:31 markus Exp $

.PATH:		${.CURDIR}/..

PROG=	ssh-proxy

BINDIR=	/usr/sbin
NOMAN=	yes

SRCS=	ssh-proxy.c readconf.c

.include <bsd.prog.mk>

DPADD+=	${LIBCRYPTO} ${LIBUTIL} ${LIBZ} ${LIBEVENT}
LDADD+=	-lcrypto -lutil -lz -levent
