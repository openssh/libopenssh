#	$OpenBSD$

.include <bsd.own.mk>
.include <bsd.obj.mk>

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
#CDIAGFLAGS+=	-Wno-unused-parameter #-Wno-error=unused-parameter
.if (${CC:L} == "gcc" || ${CC:L} == "cc")
CDIAGFLAGS+=	-Wbounded
.endif

DEBUG=-g

CFLAGS+=-I${.CURDIR}/../test_helper -I${.CURDIR}/../../ssh

.if exists(${.CURDIR}/../test_helper/${__objdir})
LDADD+=-L${.CURDIR}/../test_helper/${__objdir} -ltest_helper
DPADD+=${.CURDIR}/../test_helper/${__objdir}/libtest_helper.a
.else
LDADD+=-L${.CURDIR}/../test_helper -ltest_helper
DPADD+=${.CURDIR}/../test_helper/libtest_helper.a
.endif

.if exists(${.CURDIR}/../../ssh/lib/${__objdir})
LDADD+=-L${.CURDIR}/../../ssh/lib/${__objdir} -lssh
DPADD+=${.CURDIR}/../../ssh/lib/${__objdir}/libssh.a
.else
LDADD+=-L${.CURDIR}/../../ssh/lib -lssh
DPADD+=${.CURDIR}/../../ssh/lib/libssh.a
.endif

LDADD+= -lcrypto
DPADD+= ${LIBCRYPTO}

.if defined(LEAKMALLOC)
DEBUG=		-g
COPTS=		-O0
LEAKMALLOC_DIR=	${.CURDIR}/../../leakmalloc/leakmalloc
CFLAGS+=	-I${LEAKMALLOC_DIR} -DWITH_LEAKMALLOC 
LDFLAGS+=	-L/usr/local/lib
LDADD+=		-lleakmalloc -lexecinfo
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

