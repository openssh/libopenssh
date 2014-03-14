/* $OpenBSD: monitor_wrap.c,v 1.76 2013/05/17 00:13:13 djm Exp $ */
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * Copyright 2002 Markus Friedl <markus@openbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/queue.h>

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

#include "xmalloc.h"
#include "ssh.h"
#include "dh.h"
#include "sshbuf.h"
#include "key.h"
#include "cipher.h"
#include "kex.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "packet.h"
#include "mac.h"
#include "log.h"
#include <zlib.h>
#include "monitor.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "atomicio.h"
#include "monitor_fdpass.h"
#include "misc.h"
#include "schnorr.h"
#include "jpake.h"
#include "uuencode.h"

#include "channels.h"
#include "session.h"
#include "servconf.h"
#include "roaming.h"
#include "err.h"

/* Imports */
extern int compat20;
extern struct monitor *pmonitor;
extern struct sshbuf *loginmsg;
extern ServerOptions options;

void
mm_log_handler(LogLevel level, const char *msg, void *ctx)
{
	struct sshbuf *log_msg;
	struct monitor *mon = (struct monitor *)ctx;
	int r;

	if (mon->m_log_sendfd == -1)
		fatal("%s: no log channel", __func__);

	if ((log_msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	/*
	 * Placeholder for packet length. Will be filled in with the actual
	 * packet length once the packet has been constucted. This saves
	 * fragile math.
	 */
	if ((r = sshbuf_put_u32(log_msg, 0)) != 0 ||
	    (r = sshbuf_put_u32(log_msg, level)) != 0 ||
	    (r = sshbuf_put_cstring(log_msg, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	POKE_U32(sshbuf_ptr(log_msg), sshbuf_len(log_msg) - 4);
	if (atomicio(vwrite, mon->m_log_sendfd,
	    (u_char *)sshbuf_ptr(log_msg),
	    sshbuf_len(log_msg)) != sshbuf_len(log_msg))
		fatal("%s: write: %s", __func__, strerror(errno));
	sshbuf_free(log_msg);
}

int
mm_is_monitor(void)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	return (pmonitor && pmonitor->m_pid > 0);
}

void
mm_request_send(int sock, enum monitor_reqtype type, struct sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3("%s entering: type %d", __func__, type);

	put_u32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	if (atomicio(vwrite, sock, buf, sizeof(buf)) != sizeof(buf))
		fatal("%s: write: %s", __func__, strerror(errno));
	if (atomicio(vwrite, sock, (u_char *)sshbuf_ptr(m), mlen) != mlen)
		fatal("%s: write: %s", __func__, strerror(errno));
}

void
mm_request_receive(int sock, struct sshbuf *m)
{
	u_char buf[4], *p;
	u_int msg_len;
	int r;

	debug3("%s entering", __func__);

	if (atomicio(read, sock, buf, sizeof(buf)) != sizeof(buf)) {
		if (errno == EPIPE)
			cleanup_exit(255);
		fatal("%s: read: %s", __func__, strerror(errno));
	}
	msg_len = get_u32(buf);
	if (msg_len > 256 * 1024)
		fatal("%s: read: bad msg_len %d", __func__, msg_len);
	sshbuf_reset(m);
	if ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (atomicio(read, sock, p, msg_len) != msg_len)
		fatal("%s: read: %s", __func__, strerror(errno));
}

void
mm_request_receive_expect(int sock, enum monitor_reqtype type, struct sshbuf *m)
{
	u_char rtype;
	int r;

	debug3("%s entering: type %d", __func__, type);

	mm_request_receive(sock, m);
	if ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (rtype != type)
		fatal("%s: read: rtype %d != type %d", __func__,
		    rtype, type);
}

DH *
mm_choose_dh(int min, int nbits, int max)
{
	BIGNUM *p, *g;
	int r;
	u_char success = 0;
	struct sshbuf *m;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3("%s: waiting for MONITOR_ANS_MODULI", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	if ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (success == 0)
		fatal("%s: MONITOR_ANS_MODULI failed", __func__);

	if ((p = BN_new()) == NULL)
		fatal("%s: BN_new failed", __func__);
	if ((g = BN_new()) == NULL)
		fatal("%s: BN_new failed", __func__);
	if ((r = sshbuf_get_bignum2(m, p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, g)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: remaining %zu", __func__, sshbuf_len(m));
	sshbuf_free(m);

	return (dh_new_group(g, p));
}

int
mm_sshkey_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
    u_char *data, size_t datalen, u_int compat)
{
	struct kex *kex = *pmonitor->m_pkex;
	struct sshbuf *m;
	int r;

	debug3("%s entering", __func__);
	if (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		fatal("%s: datalen too large: %zu", __func__, datalen);
	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u32(m, kex->host_key_index(key))) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3("%s: waiting for MONITOR_ANS_SIGN", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	if ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	return (0);
}

struct passwd *
mm_getpwnamallow(const char *username)
{
	struct sshbuf *m;
	struct passwd *pw;
	size_t len;
	u_int i;
	u_char c;
	ServerOptions *newopts;
	int r;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3("%s: waiting for MONITOR_ANS_PWNAM", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	if ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (c == 0) {
		pw = NULL;
		goto out;
	}
	if ((r = sshbuf_get_string(m, (u_char **)&pw, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (len != sizeof(*pw))
		fatal("%s: struct passwd size mismatch", __func__);
	if ((r = sshbuf_get_cstring(m, &pw->pw_name, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_class, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

out:
	/* copy options block as a Match directive may have changed some */
	if ((r = sshbuf_get_string(m, (u_char **)&newopts, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (len != sizeof(*newopts))
		fatal("%s: option block size mismatch", __func__);

#define M_CP_STROPT(x) do { \
		if (newopts->x != NULL) \
			if ((r = sshbuf_get_cstring(m, &newopts->x, \
			    NULL)) != 0) \
				fatal("%s: buffer error: %s", \
				    __func__, ssh_err(r)); \
	} while (0)
#define M_CP_STRARRAYOPT(x, nx) do { \
		for (i = 0; i < newopts->nx; i++) \
			if ((r = sshbuf_get_cstring(m, &(newopts->x[i]), \
			    NULL)) != 0) \
				fatal("%s: buffer error: %s", \
				    __func__, ssh_err(r)); \
	} while (0)
	/* See comment in servconf.h */
	COPY_MATCH_STRING_OPTS();
#undef M_CP_STROPT
#undef M_CP_STRARRAYOPT

	copy_set_server_options(&options, newopts, 1);
	free(newopts);

	sshbuf_free(m);

	return (pw);
}

char *
mm_auth2_read_banner(void)
{
	struct sshbuf *m;
	char *banner;
	int r;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	if ((r = sshbuf_get_cstring(m, &banner, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	if (strlen(banner) == 0) {
		free(banner);
		banner = NULL;
	}
	return (banner);
}

/* Inform the privileged process about service and style */

void
mm_inform_authserv(char *service, char *style)
{
	struct sshbuf *m;
	int r;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
int
mm_auth_password(struct authctxt *authctxt, char *password)
{
	struct sshbuf *m;
	int r;
	u_int authenticated = 0;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3("%s: waiting for MONITOR_ANS_AUTHPASSWORD", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_AUTHPASSWORD, m);

	if ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(m);

	debug3("%s: user %sauthenticated",
	    __func__, authenticated ? "" : "not ");
	return (authenticated);
}

int
mm_user_key_allowed(struct passwd *pw, struct sshkey *key)
{
	return (mm_key_allowed(MM_USERKEY, NULL, NULL, key));
}

int
mm_hostbased_key_allowed(struct passwd *pw, char *user, char *host,
    struct sshkey *key)
{
	return (mm_key_allowed(MM_HOSTKEY, user, host, key));
}

int
mm_auth_rhosts_rsa_key_allowed(struct passwd *pw, char *user,
    char *host, struct sshkey *key)
{
	int ret;

	key->type = KEY_RSA; /* XXX hack for key_to_blob */
	ret = mm_key_allowed(MM_RSAHOSTKEY, user, host, key);
	key->type = KEY_RSA1;
	return (ret);
}

int
mm_key_allowed(enum mm_keytype type, char *user, char *host,
    struct sshkey *key)
{
	struct sshbuf *m;
	u_char *blob;
	size_t len;
	int r;
	u_int allowed = 0, have_forced = 0;

	debug3("%s entering", __func__);

	/* Convert the key to a blob and the pass it over */
	if ((r = sshkey_to_blob(key, &blob, &len)) != 0) {
		error("%s: key_to_blob: %s", __func__, ssh_err(r));
		return (0);
	}

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshbuf_put_string(m, blob, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	free(blob);

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3("%s: waiting for MONITOR_ANS_KEYALLOWED", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_KEYALLOWED, m);

	if ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* fake forced command */
	auth_clear_options();
	if ((r = sshbuf_get_u32(m, &have_forced)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	forced_command = have_forced ? xstrdup("true") : NULL;

	sshbuf_free(m);

	return (allowed);
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

int
mm_sshkey_verify(struct sshkey *key, u_char *sig, size_t siglen,
    const u_char *data, size_t datalen, u_int compat)
{
	struct sshbuf *m;
	u_char *blob;
	size_t len;
	int r;
	u_int verified = 0;

	debug3("%s entering", __func__);

	if (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		fatal("%s: datalen too large: %zu", __func__, datalen);
	/* Convert the key to a blob and the pass it over */
	if ((r = sshkey_to_blob(key, &blob, &len)) != 0) {
		error("%s: sshkey_to_blob failed: %s", __func__, ssh_err(r));
		return (0);
	}

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_string(m, blob, len)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	free(blob);

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3("%s: waiting for MONITOR_ANS_KEYVERIFY", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_KEYVERIFY, m);

	if ((r = sshbuf_get_u32(m, &verified)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(m);

	return (verified);
}

void
mm_send_keystate(struct monitor *monitor)
{
	struct ssh *ssh = active_state;		/* XXX */
	struct sshbuf *m;
	int r;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal("%s: get_state failed: %s",
		    __func__, ssh_err(r));
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3("%s: Finished sending state", __func__);
	sshbuf_free(m);
}

int
mm_pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
{
	struct sshbuf *m;
	char *p, *msg;
	int r, tmp1 = -1, tmp2 = -1;
	u_int success = 0;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	if ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error("%s: cannot allocate fds for pty", __func__);
		if (tmp1 > 0)
			close(tmp1);
		if (tmp2 > 0)
			close(tmp2);
		return 0;
	}
	close(tmp1);
	close(tmp2);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3("%s: waiting for MONITOR_ANS_PTY", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	if ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (success == 0) {
		debug3("%s: pty alloc failed", __func__);
		sshbuf_free(m);
		return (0);
	}
	if ((r = sshbuf_get_cstring(m, &p, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	free(p);

	if ((r = sshbuf_put(loginmsg, msg, strlen(msg))) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	free(msg);

	if ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal("%s: receive fds failed", __func__);

	/* Success */
	return (1);
}

void
mm_session_pty_cleanup2(Session *s)
{
	struct sshbuf *m;
	int r;

	if (s->ttyfd == -1)
		return;
	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	if (s->ptymaster != -1 && close(s->ptymaster) < 0)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

/* Request process termination */

void
mm_terminate(void)
{
	struct sshbuf *m;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

int
mm_ssh1_session_key(BIGNUM *num)
{
	int r;
	u_int rsafail;
	struct sshbuf *m;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_bignum2(m, num)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SESSKEY, m);

	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SESSKEY, m);

	if ((r = sshbuf_get_u32(m, &rsafail)) != 0 ||
	    (r = sshbuf_get_bignum2(m, num)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(m);

	return (rsafail);
}

static void
mm_chall_setup(char **name, char **infotxt, u_int *numprompts,
    char ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, sizeof(char *));
	*echo_on = xcalloc(*numprompts, sizeof(u_int));
	(*echo_on)[0] = 0;
}

int
mm_bsdauth_query(void *ctx, char **name, char **infotxt,
   u_int *numprompts, char ***prompts, u_int **echo_on)
{
	struct sshbuf *m;
	u_int success;
	char *challenge;
	int r;

	debug3("%s: entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_BSDAUTHQUERY,
	    m);
	if ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (success == 0) {
		debug3("%s: no challenge", __func__);
		sshbuf_free(m);
		return (-1);
	}

	/* Get the challenge, and format the response */
	if ((r = sshbuf_get_cstring(m, &challenge, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3("%s: received challenge: %s", __func__, challenge);

	return (0);
}

int
mm_bsdauth_respond(void *ctx, u_int numresponses, char **responses)
{
	struct sshbuf *m;
	int r;
	u_int authok;

	debug3("%s: entering", __func__);
	if (numresponses != 1)
		return (-1);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	if ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	return ((authok == 0) ? -1 : 0);
}


void
mm_ssh1_session_id(u_char session_id[16])
{
	struct sshbuf *m;

	debug3("%s entering", __func__);

	if ((m = sshbuf_from(session_id, 16)) == NULL)
		fatal("%s: sshbuf_from failed", __func__);

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SESSID, m);
	sshbuf_free(m);
}

int
mm_auth_rsa_key_allowed(struct passwd *pw, BIGNUM *client_n,
    struct sshkey **rkey)
{
	struct sshbuf *m;
	struct sshkey *key;
	u_char *blob;
	size_t blen;
	int r;
	u_int allowed = 0, have_forced = 0;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_bignum2(m, client_n)) != 0)
		fatal("%s: A buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_RSAKEYALLOWED, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_RSAKEYALLOWED,
	    m);

	if ((r = sshbuf_get_u32(m, &allowed)) != 0)
		fatal("%s: B buffer error: %s", __func__, ssh_err(r));

	/* fake forced command */
	auth_clear_options();
	if ((r = sshbuf_get_u32(m, &have_forced)) != 0)
		fatal("%s: C buffer error: %s", __func__, ssh_err(r));
	forced_command = have_forced ? xstrdup("true") : NULL;

	if (allowed && rkey != NULL) {
		if ((r = sshbuf_get_string(m, &blob, &blen)) != 0)
			fatal("%s: D buffer error: %s", __func__, ssh_err(r));
		if ((r = sshkey_from_blob(blob, blen, &key)) != 0)
			fatal("%s: key_from_blob failed: %s",
			    __func__, ssh_err(r));
		*rkey = key;
		free(blob);
	}
	sshbuf_free(m);

	return (allowed);
}

BIGNUM *
mm_auth_rsa_generate_challenge(struct sshkey *key)
{
	struct sshbuf *m;
	BIGNUM *challenge;
	u_char *blob;
	size_t blen;
	int r;

	debug3("%s entering", __func__);

	if ((challenge = BN_new()) == NULL)
		fatal("%s: BN_new failed", __func__);

	key->type = KEY_RSA;    /* XXX cheat for key_to_blob */
	if ((r = sshkey_to_blob(key, &blob, &blen)) != 0)
		fatal("%s: key_to_blob failed: %s", __func__, ssh_err(r));
	key->type = KEY_RSA1;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_string(m, blob, blen)) != 0)
		fatal("%s: E buffer error: %s", __func__, ssh_err(r));
	free(blob);

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_RSACHALLENGE, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_RSACHALLENGE, m);

	if ((r = sshbuf_get_bignum2(m, challenge)) != 0)
		fatal("%s: F buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	return (challenge);
}

int
mm_auth_rsa_verify_response(struct sshkey *key, BIGNUM *p, u_char response[16])
{
	struct sshbuf *m;
	u_char *blob;
	size_t blen;
	int r;
	u_int success = 0;

	debug3("%s entering", __func__);

	key->type = KEY_RSA;    /* XXX cheat for key_to_blob */
	if ((r = sshkey_to_blob(key, &blob, &blen)) != 0)
		fatal("%s: key_to_blob failed: %s", __func__, ssh_err(r));
	key->type = KEY_RSA1;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_string(m, blob, blen)) != 0 ||
	    (r = sshbuf_put_string(m, response, 16)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	free(blob);

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_RSARESPONSE, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_RSARESPONSE, m);

	if ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	return (success);
}

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	struct sshbuf *m;
	OM_uint32 major;
	int r;

	/* Client doesn't get to see the context */
	*ctx = NULL;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	if ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(m);
	return (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flags)
{
	struct sshbuf *m;
	OM_uint32 major;
	size_t len;
	int r;
	u_char *value;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_string(m, in->value, in->length)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	if ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = sshbuf_get_string(m, &value, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	out->value = value;
	out->length = len;
	if (flags) {
		if ((r = sshbuf_get_u32(m, flags)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	sshbuf_free(m);

	return (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	struct sshbuf *m;
	OM_uint32 major;
	int r;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_string(m, gssbuf->value, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->value, gssmic->length)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSCHECKMIC,
	    m);

	if ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);
	return(major);
}

int
mm_ssh_gssapi_userok(char *user)
{
	struct sshbuf *m;
	int r;
	u_int authenticated = 0;

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSUSEROK,
				  m);

	if ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(m);
	debug3("%s: user %sauthenticated",__func__,
	    authenticated ? "" : "not ");
	return (authenticated);
}
#endif /* GSSAPI */

#ifdef JPAKE
void
mm_auth2_jpake_get_pwdata(struct authctxt *authctxt, BIGNUM **s,
    char **hash_scheme, char **salt)
{
	struct sshbuf *m;
	int r;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	mm_request_send(pmonitor->m_recvfd,
	    MONITOR_REQ_JPAKE_GET_PWDATA, m);

	debug3("%s: waiting for MONITOR_ANS_JPAKE_GET_PWDATA", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_JPAKE_GET_PWDATA, m);

	if ((r = sshbuf_get_cstring(m, hash_scheme, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, salt, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(m);
}

void
mm_jpake_step1(struct modp_group *grp,
    u_char **id, u_int *id_len,
    BIGNUM **priv1, BIGNUM **priv2, BIGNUM **g_priv1, BIGNUM **g_priv2,
    u_char **priv1_proof, u_int *priv1_proof_len,
    u_char **priv2_proof, u_int *priv2_proof_len)
{
	struct sshbuf *m;
	size_t len, len1, len2;
	int r;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	mm_request_send(pmonitor->m_recvfd,
	    MONITOR_REQ_JPAKE_STEP1, m);

	debug3("%s: waiting for MONITOR_ANS_JPAKE_STEP1", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_JPAKE_STEP1, m);

	if ((*priv1 = BN_new()) == NULL ||
	    (*priv2 = BN_new()) == NULL ||
	    (*g_priv1 = BN_new()) == NULL ||
	    (*g_priv2 = BN_new()) == NULL)
		fatal("%s: BN_new", __func__);

	if ((r = sshbuf_get_string(m, id, &len)) != 0 ||
	    /* priv1 and priv2 are, well, private */
	    (r = sshbuf_get_bignum2(m, *g_priv1)) != 0 ||
	    (r = sshbuf_get_bignum2(m, *g_priv2)) != 0 ||
	    (r = sshbuf_get_string(m, priv1_proof, &len1)) != 0 ||
	    (r = sshbuf_get_string(m, priv2_proof, &len2)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	*id_len = len;
	*priv1_proof_len = len1;
	*priv2_proof_len = len2;

	sshbuf_free(m);
}

void
mm_jpake_step2(struct modp_group *grp, BIGNUM *s,
    BIGNUM *mypub1, BIGNUM *theirpub1, BIGNUM *theirpub2, BIGNUM *mypriv2,
    const u_char *theirid, u_int theirid_len,
    const u_char *myid, u_int myid_len,
    const u_char *theirpub1_proof, u_int theirpub1_proof_len,
    const u_char *theirpub2_proof, u_int theirpub2_proof_len,
    BIGNUM **newpub,
    u_char **newpub_exponent_proof, u_int *newpub_exponent_proof_len)
{
	struct sshbuf *m;
	size_t len;
	int r;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	/* monitor already has all bignums except theirpub1, theirpub2 */
	if ((r = sshbuf_put_bignum2(m, theirpub1)) != 0 ||
	    (r = sshbuf_put_bignum2(m, theirpub2)) != 0 ||
	    /* monitor already knows our id */
	    (r = sshbuf_put_string(m, theirid, theirid_len)) != 0 ||
	    (r = sshbuf_put_string(m, theirpub1_proof,
	    theirpub1_proof_len)) != 0 ||
	    (r = sshbuf_put_string(m, theirpub2_proof, theirpub2_proof_len)))
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd,
	    MONITOR_REQ_JPAKE_STEP2, m);

	debug3("%s: waiting for MONITOR_ANS_JPAKE_STEP2", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_JPAKE_STEP2, m);

	if ((*newpub = BN_new()) == NULL)
		fatal("%s: BN_new", __func__);

	if ((r = sshbuf_get_bignum2(m, *newpub)) != 0 ||
	    (r = sshbuf_get_string(m, newpub_exponent_proof, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	*newpub_exponent_proof_len = len;

	sshbuf_free(m);
}

void
mm_jpake_key_confirm(struct modp_group *grp, BIGNUM *s, BIGNUM *step2_val,
    BIGNUM *mypriv2, BIGNUM *mypub1, BIGNUM *mypub2,
    BIGNUM *theirpub1, BIGNUM *theirpub2,
    const u_char *my_id, u_int my_id_len,
    const u_char *their_id, u_int their_id_len,
    const u_char *sess_id, u_int sess_id_len,
    const u_char *theirpriv2_s_proof, u_int theirpriv2_s_proof_len,
    BIGNUM **k,
    u_char **confirm_hash, u_int *confirm_hash_len)
{
	struct sshbuf *m;
	size_t len;
	int r;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	/* monitor already has all bignums except step2_val */
	if ((r = sshbuf_put_bignum2(m, step2_val)) != 0 ||
	    /* monitor already knows all the ids */
	    (r = sshbuf_put_string(m, theirpriv2_s_proof,
	    theirpriv2_s_proof_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(pmonitor->m_recvfd,
	    MONITOR_REQ_JPAKE_KEY_CONFIRM, m);

	debug3("%s: waiting for MONITOR_ANS_JPAKE_KEY_CONFIRM", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_JPAKE_KEY_CONFIRM, m);

	/* 'k' is sensitive and stays in the monitor */
	if ((r = sshbuf_get_string(m, confirm_hash, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	*confirm_hash_len = len;

	sshbuf_free(m);
}

int
mm_jpake_check_confirm(const BIGNUM *k,
    const u_char *peer_id, u_int peer_id_len,
    const u_char *sess_id, u_int sess_id_len,
    const u_char *peer_confirm_hash, u_int peer_confirm_hash_len)
{
	struct sshbuf *m;
	int r, success = 0;

	debug3("%s entering", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	/* k is dummy in slave, ignored */
	/* monitor knows all the ids */
	if ((r = sshbuf_put_string(m, peer_confirm_hash,
	    peer_confirm_hash_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(pmonitor->m_recvfd,
	    MONITOR_REQ_JPAKE_CHECK_CONFIRM, m);

	debug3("%s: waiting for MONITOR_ANS_JPAKE_CHECK_CONFIRM", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_JPAKE_CHECK_CONFIRM, m);

	if ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(m);

	debug3("%s: success = %d", __func__, success);
	return success;
}
#endif /* JPAKE */
