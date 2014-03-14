/* $OpenBSD: monitor.c,v 1.126 2013/06/21 00:34:49 djm Exp $ */
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
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <openssl/dh.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "atomicio.h"
#include "xmalloc.h"
#include "ssh.h"
#include "key.h"
#include "sshbuf.h"
#include "hostfile.h"
#include "auth.h"
#include "cipher.h"
#include "kex.h"
#include "dh.h"
#include <zlib.h>
#include "packet.h"
#include "auth-options.h"
#include "sshpty.h"
#include "channels.h"
#include "session.h"
#include "sshlogin.h"
#include "canohost.h"
#include "log.h"
#include "servconf.h"
#include "monitor.h"
#include "monitor_mm.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "monitor_fdpass.h"
#include "misc.h"
#include "compat.h"
#include "ssh2.h"
#include "jpake.h"
#include "roaming.h"
#include "err.h"

#ifdef GSSAPI
static Gssctxt *gsscontext = NULL;
#endif

/* Imports */
extern ServerOptions options;
extern u_int utmp_len;
extern u_char session_id[];
extern struct sshbuf *loginmsg;

/* State exported from the child */
static struct sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

int mm_answer_moduli(int, struct sshbuf *);
int mm_answer_sign(int, struct sshbuf *);
int mm_answer_pwnamallow(int, struct sshbuf *);
int mm_answer_auth2_read_banner(int, struct sshbuf *);
int mm_answer_authserv(int, struct sshbuf *);
int mm_answer_authpassword(int, struct sshbuf *);
int mm_answer_bsdauthquery(int, struct sshbuf *);
int mm_answer_bsdauthrespond(int, struct sshbuf *);
int mm_answer_skeyquery(int, struct sshbuf *);
int mm_answer_skeyrespond(int, struct sshbuf *);
int mm_answer_keyallowed(int, struct sshbuf *);
int mm_answer_keyverify(int, struct sshbuf *);
int mm_answer_pty(int, struct sshbuf *);
int mm_answer_pty_cleanup(int, struct sshbuf *);
int mm_answer_term(int, struct sshbuf *);
int mm_answer_rsa_keyallowed(int, struct sshbuf *);
int mm_answer_rsa_challenge(int, struct sshbuf *);
int mm_answer_rsa_response(int, struct sshbuf *);
int mm_answer_sesskey(int, struct sshbuf *);
int mm_answer_sessid(int, struct sshbuf *);
int mm_answer_jpake_get_pwdata(int, struct sshbuf *);
int mm_answer_jpake_step1(int, struct sshbuf *);
int mm_answer_jpake_step2(int, struct sshbuf *);
int mm_answer_jpake_key_confirm(int, struct sshbuf *);
int mm_answer_jpake_check_confirm(int, struct sshbuf *);

#ifdef GSSAPI
int mm_answer_gss_setup_ctx(int, struct sshbuf *);
int mm_answer_gss_accept_ctx(int, struct sshbuf *);
int mm_answer_gss_userok(int, struct sshbuf *);
int mm_answer_gss_checkmic(int, struct sshbuf *);
#endif

static int monitor_read_log(struct monitor *);

static struct authctxt *authctxt;
static BIGNUM *ssh1_challenge = NULL;	/* used for ssh1 rsa auth */

/* local state for key verify */
static u_char *key_blob = NULL;
static u_int key_bloblen = 0;
static int key_blobtype = MM_NOKEY;
static char *hostbased_cuser = NULL;
static char *hostbased_chost = NULL;
static char *auth_method = "unknown";
static char *auth_submethod = NULL;
static u_int session_id2_len = 0;
static u_char *session_id2 = NULL;
static pid_t monitor_child_pid;

struct mon_table {
	enum monitor_reqtype type;
	int flags;
	int (*f)(int, struct sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

struct mon_table mon_dispatch_proto20[] = {
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#ifdef GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_setup_ctx},
    {MONITOR_REQ_GSSSTEP, MON_ISAUTH, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_AUTH, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ISAUTH, mm_answer_gss_checkmic},
#endif
#ifdef JPAKE
    {MONITOR_REQ_JPAKE_GET_PWDATA, MON_ONCE, mm_answer_jpake_get_pwdata},
    {MONITOR_REQ_JPAKE_STEP1, MON_ISAUTH, mm_answer_jpake_step1},
    {MONITOR_REQ_JPAKE_STEP2, MON_ONCE, mm_answer_jpake_step2},
    {MONITOR_REQ_JPAKE_KEY_CONFIRM, MON_ONCE, mm_answer_jpake_key_confirm},
    {MONITOR_REQ_JPAKE_CHECK_CONFIRM, MON_AUTH, mm_answer_jpake_check_confirm},
#endif
    {0, 0, NULL}
};

struct mon_table mon_dispatch_postauth20[] = {
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_TERM, 0, mm_answer_term},
    {0, 0, NULL}
};

struct mon_table mon_dispatch_proto15[] = {
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_SESSKEY, MON_ONCE, mm_answer_sesskey},
    {MONITOR_REQ_SESSID, MON_ONCE, mm_answer_sessid},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
    {MONITOR_REQ_RSAKEYALLOWED, MON_ISAUTH|MON_ALOG, mm_answer_rsa_keyallowed},
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH|MON_ALOG, mm_answer_keyallowed},
    {MONITOR_REQ_RSACHALLENGE, MON_ONCE, mm_answer_rsa_challenge},
    {MONITOR_REQ_RSARESPONSE, MON_ONCE|MON_AUTHDECIDE, mm_answer_rsa_response},
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
    {0, 0, NULL}
};

struct mon_table mon_dispatch_postauth15[] = {
    {MONITOR_REQ_PTY, MON_ONCE, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, MON_ONCE, mm_answer_pty_cleanup},
    {MONITOR_REQ_TERM, 0, mm_answer_term},
    {0, 0, NULL}
};

struct mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */

static void
monitor_permit(struct mon_table *ent, enum monitor_reqtype type, int permit)
{
	while (ent->f != NULL) {
		if (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			return;
		}
		ent++;
	}
}

static void
monitor_permit_authentications(int permit)
{
	struct mon_table *ent = mon_dispatch;

	while (ent->f != NULL) {
		if (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

void
monitor_child_preauth(struct authctxt *_authctxt, struct monitor *pmonitor)
{
	struct mon_table *ent;
	int authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	close(pmonitor->m_recvfd);
	close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = _authctxt;
	memset(authctxt, 0, sizeof(*authctxt));

	if (compat20) {
		mon_dispatch = mon_dispatch_proto20;

		/* Permit requests for moduli and signatures */
		monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	} else {
		mon_dispatch = mon_dispatch_proto15;

		monitor_permit(mon_dispatch, MONITOR_REQ_SESSKEY, 1);
	}

	/* The first few requests do not require asynchronous access */
	while (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = NULL;
		authenticated = (monitor_read(pmonitor, mon_dispatch, &ent) == 1);

		/* Special handling for multiple required authentications */
		if (options.num_auth_methods != 0) {
			if (!compat20)
				fatal("AuthenticationMethods is not supported"
				    "with SSH protocol 1");
			if (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3("%s: method %s: partial", __func__,
				    auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		if (authenticated) {
			if (!(ent->flags & MON_AUTHDECIDE))
				fatal("%s: unexpected authentication from %d",
				    __func__, ent->type);
			if (authctxt->pw->pw_uid == 0 &&
			    !auth_root_allowed(auth_method))
				authenticated = 0;
		}
		if (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(authctxt, authenticated, partial,
			    auth_method, auth_submethod);
			if (!authenticated)
				authctxt->failures++;
		}
#ifdef JPAKE
		/* Cleanup JPAKE context after authentication */
		if (ent->flags & MON_AUTHDECIDE) {
			if (authctxt->jpake_ctx != NULL) {
				jpake_free(authctxt->jpake_ctx);
				authctxt->jpake_ctx = NULL;
			}
		}
#endif
	}

	if (!authctxt->valid)
		fatal("%s: authenticated invalid user", __func__);
	if (strcmp(auth_method, "unknown") == 0)
		fatal("%s: authentication method name unknown", __func__);

	debug("%s: %s has been authenticated by privileged process",
	    __func__, authctxt->user);

	mm_get_keystate(pmonitor);

	/* Drain any buffered messages from the child */
	while (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	close(pmonitor->m_sendfd);
	close(pmonitor->m_log_recvfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
}

static void
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

static void
monitor_child_handler(int sig)
{
	kill(monitor_child_pid, sig);
}

void
monitor_child_postauth(struct monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_set_child_handler(pmonitor->m_pid);
	signal(SIGHUP, &monitor_child_handler);
	signal(SIGTERM, &monitor_child_handler);
	signal(SIGINT, &monitor_child_handler);

	if (compat20) {
		mon_dispatch = mon_dispatch_postauth20;

		/* Permit requests for moduli and signatures */
		monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);
	} else {
		mon_dispatch = mon_dispatch_postauth15;
		monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);
	}
	if (!no_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	for (;;)
		monitor_read(pmonitor, mon_dispatch, NULL);
}

void
monitor_sync(struct monitor *pmonitor)
{
	if (options.compression) {
		/* The member allocation is not visible, so sync it */
		mm_share_sync(&pmonitor->m_zlib, &pmonitor->m_zback);
	}
}

/* Allocation functions for zlib */
static void *
mm_zalloc(struct mm_master *mm, u_int ncount, u_int size)
{
	size_t len = (size_t) size * ncount;
	void *address;

	if (len == 0 || ncount > SIZE_T_MAX / size)
		fatal("%s: mm_zalloc(%u, %u)", __func__, ncount, size);

	address = mm_malloc(mm, len);

	return (address);
}

static void
mm_zfree(struct mm_master *mm, void *address)
{
	mm_free(mm, address);
}

static int
monitor_read_log(struct monitor *pmonitor)
{
	struct sshbuf *logmsg;
	u_int len, level;
	u_char *p;
	char *msg;
	int r;

	if ((logmsg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	/* Read length */
	if ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (atomicio(read, pmonitor->m_log_recvfd, p, 4) != 4) {
		if (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug("%s: child log fd closed", __func__);
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			return -1;
		}
		fatal("%s: log fd read: %s", __func__, strerror(errno));
	}
	if ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (len <= 4 || len > 8192)
		fatal("%s: invalid log message length %u", __func__, len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	if ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (atomicio(read, pmonitor->m_log_recvfd, p, len) != len)
		fatal("%s: log fd read: %s", __func__, strerror(errno));

	/* Log it */
	if ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &msg, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (log_level_name(level) == NULL)
		fatal("%s: invalid log level %u (corrupted message?)",
		    __func__, level);
	do_log2(level, "%s [preauth]", msg);

	sshbuf_free(logmsg);
	free(msg);

	return 0;
}

int
monitor_read(struct monitor *pmonitor, struct mon_table *ent,
    struct mon_table **pent)
{
	struct sshbuf *m;
	int ret, r;
	u_char type;
	struct pollfd pfd[2];

	for (;;) {
		bzero(&pfd, sizeof(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		if (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			fatal("%s: poll: %s", __func__, strerror(errno));
		}
		if (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			continue;
		}
		if (pfd[0].revents)
			break;  /* Continues below */
	}

	if ((m = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	mm_request_receive(pmonitor->m_sendfd, m);
	if ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: checking request %d", __func__, type);

	while (ent->f != NULL) {
		if (ent->type == type)
			break;
		ent++;
	}

	if (ent->f != NULL) {
		if (!(ent->flags & MON_PERMIT))
			fatal("%s: unpermitted request %d", __func__,
			    type);
		ret = (*ent->f)(pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		if (ent->flags & MON_ONCE) {
			debug2("%s: %d used once, disabling now", __func__,
			    type);
			ent->flags &= ~MON_PERMIT;
		}

		if (pent != NULL)
			*pent = ent;

		return ret;
	}

	fatal("%s: unsupported request: %d", __func__, type);

	/* NOTREACHED */
	return (-1);
}

/* allowed key state */
static int
monitor_allowed_key(u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	if (key_blob == NULL || key_bloblen != bloblen ||
	    timingsafe_bcmp(key_blob, blob, key_bloblen))
		return (0);
	return (1);
}

static void
monitor_reset_key_state(void)
{
	/* reset state */
	free(key_blob);
	free(hostbased_cuser);
	free(hostbased_chost);
	key_blob = NULL;
	key_bloblen = 0;
	key_blobtype = MM_NOKEY;
	hostbased_cuser = NULL;
	hostbased_chost = NULL;
}

int
mm_answer_moduli(int sock, struct sshbuf *m)
{
	DH *dh;
	int r;
	u_int min, want, max;

	if ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: got parameters: %d %d %d",
	    __func__, min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	if (max < min || want < min || max < want)
		fatal("%s: bad parameters: %d %d %d",
		    __func__, min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	if (dh == NULL) {
		if ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		return (0);
	} else {
		/* Send first bignum */
		if ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh->p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh->g)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	return (0);
}

int
mm_answer_sign(int sock, struct sshbuf *m)
{
	struct sshkey *key;
	u_char *p;
	u_char *signature;
	size_t datlen, siglen;
	u_int keyid;
	int r;

	debug3("%s", __func__);

	if ((r = sshbuf_get_u32(m, &keyid)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/*
	 * Supported KEX types use SHA1 (20 bytes), SHA256 (32 bytes),
	 * SHA384 (48 bytes) and SHA512 (64 bytes).
	 */
	if (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64)
		fatal("%s: data length incorrect: %zu", __func__, datlen);

	/* save session id, it will be passed on the first call */
	if (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	if ((key = get_hostkey_by_index(keyid)) == NULL)
		fatal("%s: no hostkey from index %d", __func__, keyid);
	if ((r = sshkey_sign(key, &signature, &siglen, p, datlen,
	    active_state->compat)) != 0)
		fatal("%s: sshkey_sign failed: %s", __func__, ssh_err(r));

	debug3("%s: signature %p(%zu)", __func__, signature, siglen);

	sshbuf_reset(m);
	if ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	free(p);
	free(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	return (0);
}

/* Retrieves the password entry and also checks if the user is permitted */

int
mm_answer_pwnamallow(int sock, struct sshbuf *m)
{
	char *username;
	struct passwd *pwent;
	int r, allowed = 0;
	u_int i;

	debug3("%s", __func__);

	if (authctxt->attempt++ != 0)
		fatal("%s: multiple attempts for getpwnam", __func__);

	if ((r = sshbuf_get_cstring(m, &username, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	pwent = getpwnamallow(username);

	authctxt->user = xstrdup(username);
	setproctitle("%s [priv]", pwent ? username : "unknown");
	free(username);

	sshbuf_reset(m);

	if (pwent == NULL) {
		if ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		authctxt->pw = fakepw();
		goto out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	if ((r = sshbuf_put_u8(m, 1)) != 0 ||
	    (r = sshbuf_put_string(m, pwent, sizeof(struct passwd))) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

 out:
	if ((r = sshbuf_put_string(m, &options, sizeof(options))) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

#define M_CP_STROPT(x) do { \
		if (options.x != NULL) \
			if ((r = sshbuf_put_cstring(m, options.x)) != 0) \
				fatal("%s: buffer error: %s", __func__, \
				    ssh_err(r)); \
	} while (0)
#define M_CP_STRARRAYOPT(x, nx) do { \
		for (i = 0; i < options.nx; i++) \
			if ((r = sshbuf_put_cstring(m, options.x[i])) != 0) \
				fatal("%s: buffer error: %s", __func__, \
				    ssh_err(r)); \
	} while (0)
	/* See comment in servconf.h */
	COPY_MATCH_STRING_OPTS();
#undef M_CP_STROPT
#undef M_CP_STRARRAYOPT

	/* Create valid auth method lists */
	if (compat20 && auth2_setup_methods_lists(authctxt) != 0) {
		/*
		 * The monitor will continue long enough to let the child
		 * run to it's packet_disconnect(), but it must not allow any
		 * authentication to succeed.
		 */
		debug("%s: no valid authentication method lists", __func__);
	}

	debug3("%s: sending MONITOR_ANS_PWNAM: %d", __func__, allowed);
	mm_request_send(sock, MONITOR_ANS_PWNAM, m);

	/* For SSHv1 allow authentication now */
	if (!compat20)
		monitor_permit_authentications(1);
	else {
		/* Allow service/style information on the auth context */
		monitor_permit(mon_dispatch, MONITOR_REQ_AUTHSERV, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_AUTH2_READ_BANNER, 1);
	}

	return (0);
}

int mm_answer_auth2_read_banner(int sock, struct sshbuf *m)
{
	char *banner;
	int r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	if ((r = sshbuf_put_cstring(m, banner != NULL ? banner : "")) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	free(banner);

	return (0);
}

int
mm_answer_authserv(int sock, struct sshbuf *m)
{
	int r;

	monitor_permit_authentications(1);

	if ((r = sshbuf_get_cstring(m, &authctxt->service, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	debug3("%s: service=%s, style=%s",
	    __func__, authctxt->service, authctxt->style);

	if (strlen(authctxt->style) == 0) {
		free(authctxt->style);
		authctxt->style = NULL;
	}

	return (0);
}

int
mm_answer_authpassword(int sock, struct sshbuf *m)
{
	static int call_count;
	char *passwd;
	int r, authenticated;
	size_t plen;

	if ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(authctxt, passwd);
	memset(passwd, 0, strlen(passwd));
	free(passwd);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending result %d", __func__, authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_count++;
	if (plen == 0 && call_count == 1)
		auth_method = "none";
	else
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	return (authenticated);
}

int
mm_answer_bsdauthquery(int sock, struct sshbuf *m)
{
	char *name, *infotxt, **prompts;
	u_int numprompts, *echo_on, success;
	int r;

	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, success)) != 0 ||
	    (success && (r = sshbuf_put_cstring(m, prompts[0])) != 0))
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending challenge success: %u", __func__, success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	if (success) {
		free(name);
		free(infotxt);
		free(prompts);
		free(echo_on);
	}

	return (0);
}

int
mm_answer_bsdauthrespond(int sock, struct sshbuf *m)
{
	char *response;
	int r, authok;

	if (authctxt->as == 0)
		fatal("%s: no bsd auth session", __func__);

	if ((r = sshbuf_get_cstring(m, &response, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	authok = options.challenge_response_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = NULL;
	debug3("%s: <%s> = <%d>", __func__, response, authok);
	free(response);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending authenticated: %d", __func__, authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	if (compat20) {
		auth_method = "keyboard-interactive";
		auth_submethod = "bsdauth";
	} else
		auth_method = "bsdauth";

	return (authok != 0);
}

int
mm_answer_keyallowed(int sock, struct sshbuf *m)
{
	struct sshkey *key;
	char *cuser, *chost;
	u_char *blob;
	size_t bloblen;
	enum mm_keytype type = 0;
	int r, allowed = 0;

	debug3("%s entering", __func__);

	if ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, NULL)) != 0 ||
	    (r = sshbuf_get_string(m, &blob, &bloblen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshkey_from_blob(blob, bloblen, &key)) != 0)
		fatal("%s: cannot parse key: %s", __func__, ssh_err(r));

	if ((compat20 && type == MM_RSAHOSTKEY) ||
	    (!compat20 && type != MM_RSAHOSTKEY))
		fatal("%s: key type and protocol mismatch", __func__);

	if (key != NULL && authctxt->valid) {
		switch (type) {
		case MM_USERKEY:
			allowed = options.pubkey_authentication &&
			    user_key_allowed(authctxt->pw, key);
			pubkey_auth_info(authctxt, key, NULL);
			auth_method = "publickey";
			if (options.pubkey_authentication && allowed != 1)
				auth_clear_options();
			break;
		case MM_HOSTKEY:
			allowed = options.hostbased_authentication &&
			    hostbased_key_allowed(authctxt->pw,
			    cuser, chost, key);
			pubkey_auth_info(authctxt, key,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			auth_method = "hostbased";
			break;
		case MM_RSAHOSTKEY:
			key->type = KEY_RSA1; /* XXX */
			allowed = options.rhosts_rsa_authentication &&
			    auth_rhosts_rsa_key_allowed(authctxt->pw,
			    cuser, chost, key);
			if (options.rhosts_rsa_authentication && allowed != 1)
				auth_clear_options();
			auth_method = "rsa";
			break;
		default:
			fatal("%s: unknown key type %d", __func__, type);
			break;
		}
	}
	if (key != NULL)
		sshkey_free(key);

	/* clear temporarily storage (used by verify) */
	monitor_reset_key_state();

	if (allowed) {
		/* Save temporarily for comparison in verify */
		key_blob = blob;
		key_bloblen = bloblen;
		key_blobtype = type;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} else {
		/* Log failed attempt */
		auth_log(authctxt, 0, 0, auth_method, NULL);
		free(blob);
		free(cuser);
		free(chost);
	}

	debug3("%s: key %p is %s",
	    __func__, key, allowed ? "allowed" : "not allowed");

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, allowed)) != 0 ||
	    (r = sshbuf_put_u32(m, forced_command != NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	if (type == MM_RSAHOSTKEY)
		monitor_permit(mon_dispatch, MONITOR_REQ_RSACHALLENGE, allowed);

	return (0);
}

static int
monitor_valid_userblob(u_char *data, u_int datalen)
{
	struct sshbuf *b;
	u_char *p, c;
	const u_char *cp;
	size_t len;
	int r, fail = 0;
	char *username, *methodname, *userstyle;

	if ((b = sshbuf_from(data, datalen)) == NULL)
		fatal("%s: sshbuf_from failed", __func__);

	if (active_state->compat & SSH_OLD_SESSIONID) {
		cp = sshbuf_ptr(b);
		len = sshbuf_len(b);
		if ((session_id2 == NULL) ||
		    (len < session_id2_len) ||
		    (timingsafe_bcmp(cp, session_id2, session_id2_len) != 0))
			fail++;
		if ((r = sshbuf_consume(b, session_id2_len)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	} else {
		if ((r = sshbuf_get_string(b, &p, &len)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		if ((session_id2 == NULL) ||
		    (len != session_id2_len) ||
		    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
			fail++;
		free(p);
	}
	if ((r = sshbuf_get_u8(b, &c)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (c != SSH2_MSG_USERAUTH_REQUEST)
		fail++;
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	if ((r = sshbuf_get_cstring(b, &username, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (strcmp(userstyle, username) != 0) {
		logit("wrong user name sent to monitor: expected %s != %.100s",
		    userstyle, username);
		fail++;
	}
	free(username);
	free(userstyle);
	if ((r = sshbuf_skip_string(b)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (active_state->compat & SSH_BUG_PKAUTH) {
		if ((r = sshbuf_get_u8(b, &c)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		if (!c)
			fail++;
	} else {
		if ((r = sshbuf_get_cstring(b, &methodname, NULL)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		if (strcmp("publickey", methodname) != 0)
			fail++;
		free(methodname);
		if ((r = sshbuf_get_u8(b, &c)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		if (!c)
			fail++;
		if ((r = sshbuf_skip_string(b)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	if ((r = sshbuf_skip_string(b)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	return (fail == 0);
}

static int
monitor_valid_hostbasedblob(u_char *data, u_int datalen, char *cuser,
    char *chost)
{
	struct sshbuf *b;
	char *username, *methodname, *rawhost, *ruser, *userstyle;
	u_char *sid, c;
	size_t len;
	int r, fail = 0;

	if ((b = sshbuf_from(data, datalen)) == NULL)
		fatal("%s: sshbuf_from failed", __func__);
	if ((r = sshbuf_get_string(b, &sid, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((session_id2 == NULL) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(sid, session_id2, session_id2_len) != 0))
		fail++;
	free(sid);

	if ((r = sshbuf_get_u8(b, &c)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (c != SSH2_MSG_USERAUTH_REQUEST)
		fail++;
	if ((r = sshbuf_get_cstring(b, &username, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	if (strcmp(userstyle, username) != 0) {
		logit("wrong user name sent to monitor: expected %s != %.100s",
		    userstyle, username);
		fail++;
	}
	free(userstyle);
	free(username);
	if ((r = sshbuf_skip_string(b)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &methodname, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (strcmp("hostbased", methodname) != 0)
		fail++;
	free(methodname);
	if ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* verify client host, strip trailing dot if necessary */
	if ((r = sshbuf_get_cstring(b, &rawhost, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (((len = strlen(rawhost)) > 0) && rawhost[len - 1] == '.')
		rawhost[len - 1] = '\0';
	if (strcmp(rawhost, chost) != 0)
		fail++;
	free(rawhost);

	/* verify client user */
	if ((r = sshbuf_get_cstring(b, &ruser, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (strcmp(ruser, cuser) != 0)
		fail++;
	free(ruser);

	if (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	return (fail == 0);
}

int
mm_answer_keyverify(int sock, struct sshbuf *m)
{
	struct sshkey *key;
	u_char *signature, *data, *blob;
	size_t signaturelen, datalen, bloblen;
	int r, ret, valid_data = 0;

	if ((r = sshbuf_get_string(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string(m, &data, &datalen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if (hostbased_cuser == NULL || hostbased_chost == NULL ||
	  !monitor_allowed_key(blob, bloblen))
		fatal("%s: bad key, not previously allowed", __func__);

	if ((r = sshkey_from_blob(blob, bloblen, &key)) != 0)
		fatal("%s: bad public key blob: %s", __func__, ssh_err(r));

	switch (key_blobtype) {
	case MM_USERKEY:
		valid_data = monitor_valid_userblob(data, datalen);
		break;
	case MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		break;
	default:
		valid_data = 0;
		break;
	}
	if (!valid_data)
		fatal("%s: bad signature data blob", __func__);

	ret = sshkey_verify(key, signature, signaturelen, data, datalen,
	    active_state->compat);
	debug3("%s: key %p signature %s",
	    __func__, key, (r == 0) ? "verified" : "unverified");

	sshkey_free(key);
	free(blob);
	free(signature);
	free(data);

	auth_method = key_blobtype == MM_USERKEY ? "publickey" : "hostbased";

	monitor_reset_key_state();

	sshbuf_reset(m);
	
	if ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	return ret == 0;
}

static void
mm_record_login(Session *s, struct passwd *pw)
{
	struct ssh *ssh = active_state;			/* XXX */
	socklen_t fromlen;
	struct sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, sizeof(from));
	fromlen = sizeof(from);
	if (ssh_packet_connection_is_on_socket(ssh)) {
		if (getpeername(ssh_packet_get_connection_in(ssh),
		    (struct sockaddr *)&from, &fromlen) < 0) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    get_remote_name_or_ip(utmp_len, options.use_dns),
	    (struct sockaddr *)&from, fromlen);
}

static void
mm_session_close(Session *s)
{
	debug3("%s: session %d pid %ld", __func__, s->self, (long)s->pid);
	if (s->ttyfd != -1) {
		debug3("%s: tty %s ptyfd %d", __func__, s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

int
mm_answer_pty(int sock, struct sshbuf *m)
{
	extern struct monitor *pmonitor;
	Session *s;
	int r, res, fd0;

	debug3("%s entering", __func__);

	sshbuf_reset(m);
	s = session_new();
	if (s == NULL)
		goto error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, sizeof(s->tty));
	if (res == 0)
		goto error;
	pty_setowner(authctxt->pw, s->tty);

	if ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* We need to trick ttyslot */
	if (dup2(s->ttyfd, 0) == -1)
		fatal("%s: dup2", __func__);

	mm_record_login(s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	if ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	if (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal("%s: send fds failed", __func__);

	/* make sure nothing uses fd 0 */
	if ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) < 0)
		fatal("%s: open(/dev/null): %s", __func__, strerror(errno));
	if (fd0 != 0)
		error("%s: fd0 %d != 0", __func__, fd0);

	/* slave is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3("%s: tty %s ptyfd %d", __func__, s->tty, s->ttyfd);

	return (0);

 error:
	if (s != NULL)
		mm_session_close(s);
	if ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	return (0);
}

int
mm_answer_pty_cleanup(int sock, struct sshbuf *m)
{
	Session *s;
	char *tty;
	int r;

	debug3("%s entering", __func__);

	if ((r = sshbuf_get_cstring(m, &tty, NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if ((s = session_by_tty(tty)) != NULL)
		mm_session_close(s);
	sshbuf_reset(m);
	free(tty);
	return (0);
}

int
mm_answer_sesskey(int sock, struct sshbuf *m)
{
	BIGNUM *p;
	int r, rsafail;

	/* Turn off permissions */
	monitor_permit(mon_dispatch, MONITOR_REQ_SESSKEY, 0);

	if ((p = BN_new()) == NULL)
		fatal("%s: BN_new", __func__);

	if ((r = sshbuf_get_bignum2(m, p)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	rsafail = ssh1_session_key(p);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, rsafail)) != 0 ||
	    (r = sshbuf_put_bignum2(m, p)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	BN_clear_free(p);

	mm_request_send(sock, MONITOR_ANS_SESSKEY, m);

	/* Turn on permissions for sessid passing */
	monitor_permit(mon_dispatch, MONITOR_REQ_SESSID, 1);

	return (0);
}

int
mm_answer_sessid(int sock, struct sshbuf *m)
{
	int r;

	debug3("%s entering", __func__);

	if (sshbuf_len(m) != 16)
		fatal("%s: bad ssh1 session id, len = %zu",
		    __func__, sshbuf_len(m));
	if ((r = sshbuf_get(m, session_id, 16)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	return (0);
}

int
mm_answer_rsa_keyallowed(int sock, struct sshbuf *m)
{
	BIGNUM *client_n;
	struct sshkey *key = NULL;
	u_char *blob = NULL;
	size_t blen = 0;
	int r, allowed = 0;

	debug3("%s entering", __func__);

	auth_method = "rsa";
	if (options.rsa_authentication && authctxt->valid) {
		if ((client_n = BN_new()) == NULL)
			fatal("%s: BN_new", __func__);
		if ((r = sshbuf_get_bignum2(m, client_n)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		allowed = auth_rsa_key_allowed(authctxt->pw, client_n, &key);
		BN_clear_free(client_n);
	}
	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, allowed)) != 0 ||
	    (r = sshbuf_put_u32(m, forced_command != NULL)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* clear temporarily storage (used by generate challenge) */
	monitor_reset_key_state();

	if (allowed && key != NULL) {
		key->type = KEY_RSA;	/* cheat for key_to_blob */
		if ((r = sshkey_to_blob(key, &blob, &blen)) != 0)
			fatal("%s: key_to_blob failed: %s",
			    __func__, ssh_err(r));
		if ((r = sshbuf_put_string(m, blob, blen)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));

		/* Save temporarily for comparison in verify */
		key_blob = blob;
		key_bloblen = blen;
		key_blobtype = MM_RSAUSERKEY;
	}
	if (key != NULL)
		sshkey_free(key);

	mm_request_send(sock, MONITOR_ANS_RSAKEYALLOWED, m);

	monitor_permit(mon_dispatch, MONITOR_REQ_RSACHALLENGE, allowed);
	monitor_permit(mon_dispatch, MONITOR_REQ_RSARESPONSE, 0);
	return (0);
}

int
mm_answer_rsa_challenge(int sock, struct sshbuf *m)
{
	struct sshkey *key = NULL;
	u_char *blob;
	size_t blen;
	int r;

	debug3("%s entering", __func__);

	if (!authctxt->valid)
		fatal("%s: authctxt not valid", __func__);
	if ((r = sshbuf_get_string(m, &blob, &blen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (!monitor_allowed_key(blob, blen))
		fatal("%s: bad key, not previously allowed", __func__);
	if (key_blobtype != MM_RSAUSERKEY && key_blobtype != MM_RSAHOSTKEY)
		fatal("%s: key type mismatch", __func__);
	if ((r = sshkey_from_blob(blob, blen, &key)) != 0)
		fatal("%s: received bad key: %s", __func__, ssh_err(r));
	if (key->type != KEY_RSA)
		fatal("%s: received bad key type %d", __func__, key->type);
	key->type = KEY_RSA1;
	if (ssh1_challenge)
		BN_clear_free(ssh1_challenge);
	ssh1_challenge = auth_rsa_generate_challenge(key);

	sshbuf_reset(m);
	if ((r = sshbuf_put_bignum2(m, ssh1_challenge)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s sending reply", __func__);
	mm_request_send(sock, MONITOR_ANS_RSACHALLENGE, m);

	monitor_permit(mon_dispatch, MONITOR_REQ_RSARESPONSE, 1);

	free(blob);
	sshkey_free(key);
	return (0);
}

int
mm_answer_rsa_response(int sock, struct sshbuf *m)
{
	struct sshkey *key = NULL;
	u_char *blob, *response;
	size_t blen, len;
	int r, success;

	debug3("%s entering", __func__);

	if (!authctxt->valid)
		fatal("%s: authctxt not valid", __func__);
	if (ssh1_challenge == NULL)
		fatal("%s: no ssh1_challenge", __func__);

	if ((r = sshbuf_get_string(m, &blob, &blen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (!monitor_allowed_key(blob, blen))
		fatal("%s: bad key, not previously allowed", __func__);
	if (key_blobtype != MM_RSAUSERKEY && key_blobtype != MM_RSAHOSTKEY)
		fatal("%s: key type mismatch: %d", __func__, key_blobtype);
	if ((r = sshkey_from_blob(blob, blen, &key)) != 0)
		fatal("%s: received bad key: %s", __func__, ssh_err(r));
	if ((r = sshbuf_get_string(m, &response, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (len != 16)
		fatal("%s: received bad response to challenge", __func__);
	success = auth_rsa_verify_response(key, ssh1_challenge, response);

	free(blob);
	sshkey_free(key);
	free(response);

	auth_method = key_blobtype == MM_RSAUSERKEY ? "rsa" : "rhosts-rsa";

	/* reset state */
	BN_clear_free(ssh1_challenge);
	ssh1_challenge = NULL;
	monitor_reset_key_state();

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, success)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(sock, MONITOR_ANS_RSARESPONSE, m);

	return (success);
}

int
mm_answer_term(int sock, struct sshbuf *req)
{
	extern struct monitor *pmonitor;
	int res, status;

	debug3("%s: tearing down sessions", __func__);

	/* The child is terminating */
	session_destroy_all(&mm_session_close);

	while (waitpid(pmonitor->m_pid, &status, 0) == -1)
		if (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

void
monitor_apply_keystate(struct monitor *pmonitor)
{
	struct ssh *ssh = active_state;	/* XXX */
	struct kex *kex;
	int r;

	debug3("%s: packet_set_state", __func__);
	if ((r = ssh_packet_set_state(ssh, child_state)) != 0)
                fatal("%s: packet_set_state: %s", __func__, ssh_err(r));
	sshbuf_free(child_state);
	child_state = NULL;

	if ((kex = ssh->kex) != 0) {
		/* XXX set callbacks */
		kex->kex[KEX_DH_GRP1_SHA1] = kexdh_server;
		kex->kex[KEX_DH_GRP14_SHA1] = kexdh_server;
		kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		kex->kex[KEX_ECDH_SHA2] = kexecdh_server;
		kex->load_host_public_key=&get_hostkey_public_by_type;
		kex->load_host_private_key=&get_hostkey_private_by_type;
		kex->host_key_index=&get_hostkey_index;
	}

	/* Update with new address */
	if (options.compression) {
		ssh_packet_set_compress_hooks(ssh, pmonitor->m_zlib,
		    (ssh_packet_comp_alloc_func *)mm_zalloc,
		    (ssh_packet_comp_free_func *)mm_zfree);
	}
	if (options.rekey_limit || options.rekey_interval)
		ssh_packet_set_rekey_limits(ssh,
		    (u_int32_t)options.rekey_limit,
		    (time_t)options.rekey_interval);
	debug3("%s: done", __func__);
}

/* This function requries careful sanity checking */

void
mm_get_keystate(struct monitor *pmonitor)
{
	debug3("%s: Waiting for new keys", __func__);

	if ((child_state = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3("%s: GOT new keys", __func__);
}


/* XXX */

#define FD_CLOSEONEXEC(x) do { \
	if (fcntl(x, F_SETFD, FD_CLOEXEC) == -1) \
		fatal("fcntl(%d, F_SETFD)", x); \
} while (0)

static void
monitor_openfds(struct monitor *mon, int do_logfds)
{
	int pair[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal("%s: socketpair: %s", __func__, strerror(errno));
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	if (do_logfds) {
		if (pipe(pair) == -1)
			fatal("%s: pipe: %s", __func__, strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} else
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

#define MM_MEMSIZE	65536

struct monitor *
monitor_init(void)
{
	struct ssh *ssh = active_state;			/* XXX */
	struct monitor *mon;

	mon = xcalloc(1, sizeof(*mon));

	monitor_openfds(mon, 1);

	/* Used to share zlib space across processes */
	if (options.compression) {
		mon->m_zback = mm_create(NULL, MM_MEMSIZE);
		mon->m_zlib = mm_create(mon->m_zback, 20 * MM_MEMSIZE);

		/* Compression needs to share state across borders */
		ssh_packet_set_compress_hooks(ssh, mon->m_zlib,
		    (ssh_packet_comp_alloc_func *)mm_zalloc,
		    (ssh_packet_comp_free_func *)mm_zfree);
	}

	return mon;
}

void
monitor_reinit(struct monitor *mon)
{
	monitor_openfds(mon, 0);
}

#ifdef GSSAPI
int
mm_answer_gss_setup_ctx(int sock, struct sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	int r;

	if ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	free(goid.elements);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, major)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	return (0);
}

int
mm_answer_gss_accept_ctx(int sock, struct sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	size_t len;
	u_char *p;
	int r;

	if ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	in.value = p;
	in.length = len;
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	free(in.value);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.value, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	if (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	return 0;
}

int
mm_answer_gss_checkmic(int sock, struct sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	size_t len;
	int r;
	u_char *p;

	if ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	gssbuf.value = p;
	gssbuf.length = len;
	if ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	mic.value = p;
	mic.length = len;

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	free(gssbuf.value);
	free(mic.value);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	if (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	return 0;
}

int
mm_answer_gss_userok(int sock, struct sshbuf *m)
{
	int r, authenticated;

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending result %d", __func__, authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	/* Monitor loop will terminate if authenticated */
	return (authenticated);
}
#endif /* GSSAPI */

#ifdef JPAKE
int
mm_answer_jpake_step1(int sock, struct sshbuf *m)
{
	struct jpake_ctx *pctx;
	u_char *x3_proof, *x4_proof;
	u_int x3_proof_len, x4_proof_len;
	int r;

	if (!options.zero_knowledge_password_authentication)
		fatal("zero_knowledge_password_authentication disabled");

	if (authctxt->jpake_ctx != NULL)
		fatal("%s: authctxt->jpake_ctx already set (%p)",
		    __func__, authctxt->jpake_ctx);
	authctxt->jpake_ctx = pctx = jpake_new();

	jpake_step1(pctx->grp,
	    &pctx->server_id, &pctx->server_id_len,
	    &pctx->x3, &pctx->x4, &pctx->g_x3, &pctx->g_x4,
	    &x3_proof, &x3_proof_len,
	    &x4_proof, &x4_proof_len);

	JPAKE_DEBUG_CTX((pctx, "step1 done in %s", __func__));

	sshbuf_reset(m);

	if ((r = sshbuf_put_string(m, pctx->server_id,
	    pctx->server_id_len)) != 0 ||
	    (r = sshbuf_put_bignum2(m, pctx->g_x3)) != 0 ||
	    (r = sshbuf_put_bignum2(m, pctx->g_x4)) != 0 ||
	    (r = sshbuf_put_string(m, x3_proof, x3_proof_len)) != 0 ||
	    (r = sshbuf_put_string(m, x4_proof, x4_proof_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending step1", __func__);
	mm_request_send(sock, MONITOR_ANS_JPAKE_STEP1, m);

	bzero(x3_proof, x3_proof_len);
	bzero(x4_proof, x4_proof_len);
	free(x3_proof);
	free(x4_proof);

	monitor_permit(mon_dispatch, MONITOR_REQ_JPAKE_GET_PWDATA, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_JPAKE_STEP1, 0);

	return 0;
}

int
mm_answer_jpake_get_pwdata(int sock, struct sshbuf *m)
{
	struct jpake_ctx *pctx = authctxt->jpake_ctx;
	char *hash_scheme, *salt;
	int r;

	if (pctx == NULL)
		fatal("%s: pctx == NULL", __func__);

	auth2_jpake_get_pwdata(authctxt, &pctx->s, &hash_scheme, &salt);

	sshbuf_reset(m);
	/* pctx->s is sensitive, not returned to slave */
	if ((r = sshbuf_put_cstring(m, hash_scheme)) != 0 ||
	    (r = sshbuf_put_cstring(m, salt)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending pwdata", __func__);
	mm_request_send(sock, MONITOR_ANS_JPAKE_GET_PWDATA, m);

	bzero(hash_scheme, strlen(hash_scheme));
	bzero(salt, strlen(salt));
	free(hash_scheme);
	free(salt);

	monitor_permit(mon_dispatch, MONITOR_REQ_JPAKE_STEP2, 1);

	return 0;
}

int
mm_answer_jpake_step2(int sock, struct sshbuf *m)
{
	struct jpake_ctx *pctx = authctxt->jpake_ctx;
	u_char *x1_proof, *x2_proof, *x4_s_proof;
	u_int x4_s_proof_len;
	size_t x1_proof_len, x2_proof_len, len;
	int r;

	if (pctx == NULL)
		fatal("%s: pctx == NULL", __func__);

	if ((pctx->g_x1 = BN_new()) == NULL ||
	    (pctx->g_x2 = BN_new()) == NULL)
		fatal("%s: BN_new", __func__);
	if ((r = sshbuf_get_bignum2(m, pctx->g_x1)) != 0 ||
	    (r = sshbuf_get_bignum2(m, pctx->g_x2)) != 0 ||
	    (r = sshbuf_get_string(m, &pctx->client_id, &len)) != 0 ||
	    (r = sshbuf_get_string(m, &x1_proof, &x1_proof_len)) != 0 ||
	    (r = sshbuf_get_string(m, &x2_proof, &x2_proof_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	pctx->client_id_len = len;

	jpake_step2(pctx->grp, pctx->s, pctx->g_x3,
	    pctx->g_x1, pctx->g_x2, pctx->x4,
	    pctx->client_id, pctx->client_id_len,
	    pctx->server_id, pctx->server_id_len,
	    x1_proof, x1_proof_len,
	    x2_proof, x2_proof_len,
	    &pctx->b,
	    &x4_s_proof, &x4_s_proof_len);

	JPAKE_DEBUG_CTX((pctx, "step2 done in %s", __func__));

	bzero(x1_proof, x1_proof_len);
	bzero(x2_proof, x2_proof_len);
	free(x1_proof);
	free(x2_proof);

	sshbuf_reset(m);

	if ((r = sshbuf_put_bignum2(m, pctx->b)) != 0 ||
	    (r = sshbuf_put_string(m, x4_s_proof, x4_s_proof_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending step2", __func__);
	mm_request_send(sock, MONITOR_ANS_JPAKE_STEP2, m);

	bzero(x4_s_proof, x4_s_proof_len);
	free(x4_s_proof);

	monitor_permit(mon_dispatch, MONITOR_REQ_JPAKE_KEY_CONFIRM, 1);

	return 0;
}

int
mm_answer_jpake_key_confirm(int sock, struct sshbuf *m)
{
	struct jpake_ctx *pctx = authctxt->jpake_ctx;
	u_char *x2_s_proof;
	size_t x2_s_proof_len;
	int r;

	if (pctx == NULL)
		fatal("%s: pctx == NULL", __func__);

	if ((pctx->a = BN_new()) == NULL)
		fatal("%s: BN_new", __func__);
	if ((r = sshbuf_get_bignum2(m, pctx->a)) != 0 ||
	    (r = sshbuf_get_string(m, &x2_s_proof, &x2_s_proof_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	jpake_key_confirm(pctx->grp, pctx->s, pctx->a,
	    pctx->x4, pctx->g_x3, pctx->g_x4, pctx->g_x1, pctx->g_x2,
	    pctx->server_id, pctx->server_id_len,
	    pctx->client_id, pctx->client_id_len,
	    session_id2, session_id2_len,
	    x2_s_proof, x2_s_proof_len,
	    &pctx->k,
	    &pctx->h_k_sid_sessid, &pctx->h_k_sid_sessid_len);

	JPAKE_DEBUG_CTX((pctx, "key_confirm done in %s", __func__));

	bzero(x2_s_proof, x2_s_proof_len);
	sshbuf_reset(m);

	/* pctx->k is sensitive, not sent */
	if ((r = sshbuf_put_string(m, pctx->h_k_sid_sessid,
	    pctx->h_k_sid_sessid_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending confirmation hash", __func__);
	mm_request_send(sock, MONITOR_ANS_JPAKE_KEY_CONFIRM, m);

	monitor_permit(mon_dispatch, MONITOR_REQ_JPAKE_CHECK_CONFIRM, 1);

	return 0;
}

int
mm_answer_jpake_check_confirm(int sock, struct sshbuf *m)
{
	int r, authenticated = 0;
	u_char *peer_confirm_hash;
	size_t peer_confirm_hash_len;
	struct jpake_ctx *pctx = authctxt->jpake_ctx;

	if (pctx == NULL)
		fatal("%s: pctx == NULL", __func__);

	if ((r = sshbuf_get_string(m, &peer_confirm_hash,
	     &peer_confirm_hash_len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	authenticated = jpake_check_confirm(pctx->k,
	    pctx->client_id, pctx->client_id_len,
	    session_id2, session_id2_len,
	    peer_confirm_hash, peer_confirm_hash_len) && authctxt->valid;

	JPAKE_DEBUG_CTX((pctx, "check_confirm done in %s", __func__));

	bzero(peer_confirm_hash, peer_confirm_hash_len);
	free(peer_confirm_hash);

	sshbuf_reset(m);
	if ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	debug3("%s: sending result %d", __func__, authenticated);
	mm_request_send(sock, MONITOR_ANS_JPAKE_CHECK_CONFIRM, m);

	monitor_permit(mon_dispatch, MONITOR_REQ_JPAKE_STEP1, 1);

	auth_method = "jpake-01@openssh.com";
	return authenticated;
}

#endif /* JPAKE */
