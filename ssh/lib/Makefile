#	$OpenBSD: Makefile,v 1.67 2013/01/17 23:00:01 djm Exp $

.PATH:		${.CURDIR}/..

LIB=	ssh
SRCS=	authfd.c authfile.c canohost.c \
	channels.c cipher.c cipher-3des1.c cipher-bf1.c \
	cleanup.c compat.c crc32.c deattack.c fatal.c \
	hostfile.c log.c match.c nchan.c packet.c readpass.c \
	rsa.c ttymodes.c xmalloc.c atomicio.c \
	key.c dispatch.c kex.c mac.c uidswap.c uuencode.c misc.c \
	ssh-dss.c ssh-rsa.c ssh-ecdsa.c dh.c kexdh.c kexgex.c kexecdh.c \
	kexdhc.c kexgexc.c kexecdhc.c msg.c progressmeter.c dns.c \
	monitor_fdpass.c umac.c addrmatch.c schnorr.c jpake.c ssh-pkcs11.c \
	krl.c \
	sshbuf-getput-basic.c \
	sshbuf-getput-crypto.c \
	sshbuf-misc.c \
	sshbuf.c \
	err.c

SRCS+=	kexdhs.c kexgexs.c kexecdhs.c
SRCS+=	ssh_api.c
SRCS+=	roaming_dummy.c

SRCS+=	umac128.c
CLEANFILES+=   umac128.c
umac128.c: umac.c Makefile
	sed \
	    -e "s/^#define UMAC_OUTPUT_LEN     8/#define UMAC_OUTPUT_LEN 16/" \
	    -e s/umac_new/umac128_new/g \
	    -e s/umac_update/umac128_update/g \
	    -e s/umac_final/umac128_final/g \
	    -e s/umac_delete/umac128_delete/g \
	    < ${.CURDIR}/../umac.c > ${.TARGET}

DEBUGLIBS= no
NOPROFILE= yes

install:
	@echo -n

.include "${.CURDIR}/../Makefile.inc"
.include <bsd.own.mk>

# XXX leave on while refactoring to ensure we don't break it.
KERBEROS5=yes

.if (${KERBEROS5:L} == "yes")
CFLAGS+= -DKRB5 -I${DESTDIR}/usr/include/kerberosV

SRCS+= gss-genr.c
CFLAGS+= -DGSSAPI
.endif # KERBEROS5

NOPIC= yes
.include <bsd.lib.mk>
