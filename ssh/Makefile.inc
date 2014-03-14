#	$OpenBSD: Makefile.inc,v 1.39 2010/10/01 23:10:48 djm Exp $

CFLAGS+=	-I${.CURDIR}/..

# enable warnings
WARNINGS=Yes

CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wextra
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wpointer-sign
CDIAGFLAGS+=	-Wno-unused-parameter #-Wno-error=unused-parameter
CDIAGFLAGS+=	-Wno-deprecated-declarations # XXX until heimdal update deprecations fixes

#DEBUG=-g

#CFLAGS+=	-DJPAKE

CFLAGS+=	-DENABLE_PKCS11
.include <bsd.own.mk>
.ifndef NOPIC
CFLAGS+=	-DHAVE_DLOPEN
.endif

.include <bsd.obj.mk>

.if !defined(LIB)
.if exists(${.CURDIR}/../lib/${__objdir})
LDADD+=         -L${.CURDIR}/../lib/${__objdir} -lssh
DPADD+=         ${.CURDIR}/../lib/${__objdir}/libssh.a
.else
LDADD+=         -L${.CURDIR}/../lib -lssh
DPADD+=         ${.CURDIR}/../lib/libssh.a
.endif
DPADD+=         ${.CURDIR}/../lib/shlib_version
LDADD+=         -lcrypto -lz
DPADD+=         ${LIBCRYPTO} ${LIBZ}
.endif

.if defined(LEAKMALLOC)
DEBUG=		-g
COPTS=		-O0
LEAKMALLOC_DIR=	${.CURDIR}/../../leakmalloc/leakmalloc
CFLAGS+=	-I${LEAKMALLOC_DIR} -DWITH_LEAKMALLOC 
LDFLAGS+=	-L/usr/local/lib
LDADD+=		-lleakmalloc -lexecinfo
CFLAGS+=	-Dmalloc=leak_malloc -Dstrdup=leak_strdup
CFLAGS+=	-Dcalloc=leak_calloc -Drealloc=leak_realloc
CFLAGS+=	-Dfree=leak_free
. if exists(${LEAKMALLOC_DIR}/${__objdir})
LDADD+=         -L${LEAKMALLOC_DIR}/${__objdir}
DPADD+=         ${LEAKMALLOC_DIR}/${__objdir}/libleakmalloc.a
. else
LDADD+=         -L${LEAKMALLOC_DIR}
DPADD+=         ${LEAKMALLOC_DIR}/libleakmalloc.a
. endif
.else
CDIAGFLAGS+=	-Wuninitialized
.endif

