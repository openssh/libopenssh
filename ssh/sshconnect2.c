/* $OpenBSD: sshconnect2.c,v 1.198 2013/06/05 12:52:38 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <unistd.h>
#include <vis.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "myproposal.h"
#include "sshconnect.h"
#include "authfile.h"
#include "dh.h"
#include "authfd.h"
#include "log.h"
#include "readconf.h"
#include "misc.h"
#include "match.h"
#include "dispatch.h"
#include "canohost.h"
#include "msg.h"
#include "pathnames.h"
#include "uidswap.h"
#include "hostfile.h"
#include "schnorr.h"
#include "jpake.h"
#include "compat.h"
#include "err.h"

#ifdef GSSAPI
#include "ssh-gss.h"
#endif

/* import */
extern char *client_version_string;
extern char *server_version_string;
extern Options options;

/*
 * SSH2 key exchange
 */

u_char *session_id2 = NULL;
u_int session_id2_len = 0;

static int
verify_host_key_callback(struct sshkey *hostkey, struct ssh *ssh)
{
	if (verify_host_key(ssh->host, ssh->hostaddr, hostkey) == -1)
		fatal("Host key verification failed.");
	return 0;
}

static char *
order_hostkeyalgs(char *host, struct sockaddr *hostaddr, u_short port)
{
	char *oavail, *avail, *first, *last, *alg, *hostname, *ret;
	size_t maxlen;
	struct hostkeys *hostkeys;
	int ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, NULL);
	hostkeys = init_hostkeys();
	for (i = 0; i < options.num_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i]);
	for (i = 0; i < options.num_system_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.system_hostfiles[i]);

	oavail = avail = xstrdup(KEX_DEFAULT_PK_ALG);
	maxlen = strlen(avail) + 1;
	first = xmalloc(maxlen);
	last = xmalloc(maxlen);
	*first = *last = '\0';

#define ALG_APPEND(to, from) \
	do { \
		if (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} while (0)

	while ((alg = strsep(&avail, ",")) && *alg != '\0') {
		if ((ktype = sshkey_type_from_name(alg)) == KEY_UNSPEC)
			fatal("%s: unknown alg %s", __func__, alg);
		if (lookup_key_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype), NULL))
			ALG_APPEND(first, alg);
		else
			ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first, *first == '\0' ? "" : ",", last);
	if (*first != '\0')
		debug3("%s: prefer hostkeyalgs: %s", __func__, first);

	free(first);
	free(last);
	free(hostname);
	free(oavail);
	free_hostkeys(hostkeys);

	return ret;
}

void
ssh_kex2(struct ssh *ssh, u_short port)
{
	int r;

	if (options.ciphers == (char *)-1) {
		logit("No valid ciphers for protocol version 2 given, using defaults.");
		options.ciphers = NULL;
	}
	if (options.ciphers != NULL) {
		myproposal[PROPOSAL_ENC_ALGS_CTOS] =
		myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	}
	myproposal[PROPOSAL_ENC_ALGS_CTOS] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS], ssh->compat);
	myproposal[PROPOSAL_ENC_ALGS_STOC] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC], ssh->compat);
	if (myproposal[PROPOSAL_ENC_ALGS_CTOS] == NULL ||
	    myproposal[PROPOSAL_ENC_ALGS_STOC] == NULL)
		fatal("no compatible ciphers found");
	if (options.compression) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "zlib@openssh.com,zlib,none";
	} else {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib@openssh.com,zlib";
	}
	if (options.macs != NULL) {
		myproposal[PROPOSAL_MAC_ALGS_CTOS] =
		myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;
	}
	if (options.hostkeyalgorithms != NULL)
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] =
		    options.hostkeyalgorithms;
	else {
		/* Prefer algorithms that we already have keys for */
		myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] =
		    order_hostkeyalgs(ssh->host, ssh->hostaddr, port);
	}
	if (options.kex_algorithms != NULL)
		myproposal[PROPOSAL_KEX_ALGS] = options.kex_algorithms;

	if (options.rekey_limit || options.rekey_interval)
		ssh_packet_set_rekey_limits(ssh,
		    (u_int32_t)options.rekey_limit,
		    (time_t)options.rekey_interval);

	/* start key exchange */
	if ((r = kex_setup(ssh, myproposal)) != 0)
		fatal("kex_setup: %s", ssh_err(r));
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kexdh_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kexdh_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kexecdh_client;
	ssh->kex->client_version_string=client_version_string;
	ssh->kex->server_version_string=server_version_string;
	ssh->kex->verify_host_key=&verify_host_key_callback;

	if ((r = ssh_dispatch_run(ssh, DISPATCH_BLOCK, &ssh->kex->done)) != 0)
		fatal("%s: ssh_dispatch_run failed: %s", __func__, ssh_err(r));

	if (options.use_roaming && !ssh->kex->roaming) {
		debug("Roaming not allowed by server");
		options.use_roaming = 0;
	}

	session_id2 = ssh->kex->session_id;
	session_id2_len = ssh->kex->session_id_len;

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	if ((r = sshpkt_start(ssh, SSH2_MSG_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	ssh_packet_write_wait(ssh);
#endif
}

/*
 * Authenticate user
 */

struct identity {
	TAILQ_ENTRY(identity) next;
	int	agent_fd;		/* >=0 if agent supports key */
	struct sshkey	*key;		/* public/private key */
	char	*filename;		/* comment for agent-only keys */
	int	tried;
	int	isprivate;		/* key points to the private key */
	int	userprovided;
};
TAILQ_HEAD(idlist, identity);

struct cauthctxt {
	const char *server_user;
	const char *local_user;
	const char *host;
	const char *service;
	struct cauthmethod *method;
	sig_atomic_t success;
	char *authlist;
	int attempt;
	/* pubkey */
	struct idlist keys;
	int agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	/* kbd-interactive */
	int info_req_seen;
	/* generic */
	void *methoddata;
#ifdef GSSAPI
	gss_OID_set gss_supported;
	u_int gss_mech;
#endif
};

struct cauthmethod {
	char	*name;		/* string to compare against server's list */
	int	(*userauth)(struct ssh *);
	void	(*cleanup)(struct ssh *);
	int	*enabled;	/* flag in option struct that enables method */
	int	*batch_flag;	/* flag in option struct that disables method */
};

int	input_userauth_service_accept(int, u_int32_t, struct ssh *);
int	input_userauth_success(int, u_int32_t, struct ssh *);
int	input_userauth_success_unexpected(int, u_int32_t, struct ssh *);
int	input_userauth_failure(int, u_int32_t, struct ssh *);
int	input_userauth_banner(int, u_int32_t, struct ssh *);
int	input_userauth_error(int, u_int32_t, struct ssh *);
int	input_userauth_info_req(int, u_int32_t, struct ssh *);
int	input_userauth_pk_ok(int, u_int32_t, struct ssh *);
int	input_userauth_passwd_changereq(int, u_int32_t, struct ssh *);
int	input_userauth_jpake_server_step1(int, u_int32_t, struct ssh *);
int	input_userauth_jpake_server_step2(int, u_int32_t, struct ssh *);
int	input_userauth_jpake_server_confirm(int, u_int32_t, struct ssh *);

int	userauth_none(struct ssh *);
int	userauth_pubkey(struct ssh *);
int	userauth_passwd(struct ssh *);
int	userauth_kbdint(struct ssh *);
int	userauth_hostbased(struct ssh *);
int	userauth_jpake(struct ssh *);

void	userauth_jpake_cleanup(struct ssh *);

#ifdef GSSAPI
int	userauth_gssapi(struct ssh *);
int	input_gssapi_response(int type, u_int32_t, struct ssh *);
int	input_gssapi_token(int type, u_int32_t, struct ssh *);
int	input_gssapi_hash(int type, u_int32_t, struct ssh *);
int	input_gssapi_error(int, u_int32_t, struct ssh *);
int	input_gssapi_errtok(int, u_int32_t, struct ssh *);
#endif

void	userauth(struct ssh *, char *);

static int sign_and_send_pubkey(struct ssh *, struct identity *);
static void pubkey_prepare(struct ssh *);
static void pubkey_cleanup(struct ssh *);
static struct sshkey *load_identity_file(char *, int);

static struct cauthmethod *authmethod_get(char *authlist);
static struct cauthmethod *authmethod_lookup(const char *name);
static char *authmethods_get(void);

struct cauthmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		NULL,
		&options.gss_authentication,
		NULL},
#endif
	{"hostbased",
		userauth_hostbased,
		NULL,
		&options.hostbased_authentication,
		NULL},
	{"publickey",
		userauth_pubkey,
		NULL,
		&options.pubkey_authentication,
		NULL},
#ifdef JPAKE
	{"jpake-01@openssh.com",
		userauth_jpake,
		userauth_jpake_cleanup,
		&options.zero_knowledge_password_authentication,
		&options.batch_mode},
#endif
	{"keyboard-interactive",
		userauth_kbdint,
		NULL,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		NULL,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		NULL,
		NULL,
		NULL},
	{NULL, NULL, NULL, NULL, NULL}
};

void
ssh_userauth2(struct ssh *ssh, const char *local_user, const char *server_user,
    Sensitive *sensitive)
{
	struct cauthctxt *authctxt;
	int r;

	if (options.challenge_response_authentication)
		options.kbd_interactive_authentication = 1;

	if (options.preferred_authentications == NULL)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	authctxt = xcalloc(1, sizeof(*authctxt));
	ssh->authctxt = authctxt;
	pubkey_prepare(ssh);
	authctxt->server_user = server_user;
	authctxt->local_user = local_user;
	authctxt->host = ssh->host;
	authctxt->service = "ssh-connection";		/* service name */
	authctxt->success = 0;
	authctxt->method = authmethod_lookup("none");
	authctxt->authlist = NULL;
	authctxt->methoddata = NULL;
	authctxt->sensitive = sensitive;
	authctxt->info_req_seen = 0;
	if (authctxt->method == NULL)
		fatal("ssh_userauth2: internal error: cannot send userauth none request");

	if ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	debug("SSH2_MSG_SERVICE_REQUEST sent");

	ssh_dispatch_init(ssh, &input_userauth_error);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_ACCEPT, &input_userauth_service_accept);
	ssh_dispatch_run(ssh, DISPATCH_BLOCK, &authctxt->success);	/* loop until success */

	pubkey_cleanup(ssh);
	ssh_dispatch_range(ssh, SSH2_MSG_USERAUTH_MIN, SSH2_MSG_USERAUTH_MAX, NULL);

	debug("Authentication succeeded (%s).", authctxt->method->name);
	free(authctxt);
	ssh->authctxt = NULL;
}

/* ARGSUSED */
int
input_userauth_service_accept(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;

	if (ssh_packet_remaining(ssh) > 0) {
		char *reply;

		if ((r = sshpkt_get_cstring(ssh, &reply, NULL)) != 0)
			goto out;
		debug2("service_accept: %s", reply);
		free(reply);
	} else {
		debug2("buggy server: service_accept w/o service");
	}
	if ((r = sshpkt_get_end(ssh)) != 0)
		goto out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	ssh_dispatch_init(ssh, &input_userauth_error);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_FAILURE, &input_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_BANNER, &input_userauth_banner);
	r = 0;
 out:
	return r;
}

void
userauth(struct ssh *ssh, char *authlist)
{
	struct cauthctxt *authctxt = ssh->authctxt;

	if (authctxt->method != NULL && authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(ssh);

	free(authctxt->methoddata);
	authctxt->methoddata = NULL;
	if (authlist == NULL) {
		authlist = authctxt->authlist;
	} else {
		free(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	for (;;) {
		struct cauthmethod *method = authmethod_get(authlist);
		if (method == NULL)
			fatal("Permission denied (%s).", authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_MSG_USERAUTH_PER_METHOD_MIN,
		    SSH2_MSG_USERAUTH_PER_METHOD_MAX, NULL);

		/* and try new method */
		if (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			break;
		} else {
			debug2("we did not send a packet, disable method");
			method->enabled = NULL;
		}
	}
}

/* ARGSUSED */
int
input_userauth_error(int type, u_int32_t seq, struct ssh *ssh)
{
	fatal("input_userauth_error: bad message during authentication: "
	    "type %d", type);
	return 0;
}

/* ARGSUSED */
int
input_userauth_banner(int type, u_int32_t seq, struct ssh *ssh)
{
	char *msg, *raw = NULL, *lang = NULL;
	size_t len;
	int r;

	debug3("input_userauth_banner");
	if ((r = sshpkt_get_cstring(ssh, &raw, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
		goto out;
	if (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO) {
		if (len > 65536)
			len = 65536;
		msg = malloc(len * 4 + 1); /* max expansion from strnvis() */
		if (msg == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		strnvis(msg, raw, len * 4 + 1, VIS_SAFE|VIS_OCTAL|VIS_NOSLASH);
		fprintf(stderr, "%s", msg);
		free(msg);
	}
	r = 0;
 out:
	free(raw);
	free(lang);
	return r;
}

/* ARGSUSED */
int
input_userauth_success(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;

	if (authctxt == NULL)
		fatal("input_userauth_success: no authentication context");
	free(authctxt->authlist);
	authctxt->authlist = NULL;
	if (authctxt->method != NULL && authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(ssh);
	free(authctxt->methoddata);
	authctxt->methoddata = NULL;
	authctxt->success = 1;			/* break out */
	return 0;
}

int
input_userauth_success_unexpected(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;

	if (authctxt == NULL)
		fatal("%s: no authentication context", __func__);

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	return 0;
}

/* ARGSUSED */
int
input_userauth_failure(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	char *authlist = NULL;
	u_char partial;
	int r;

	if (authctxt == NULL)
		fatal("input_userauth_failure: no authentication context");

	if ((r = sshpkt_get_cstring(ssh, &authlist, NULL)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &partial)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	if (partial != 0) {
		logit("Authenticated with partial success.");
		/* reset state */
		pubkey_cleanup(ssh);
		pubkey_prepare(ssh);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = NULL;
	r = 0;
 out:
	free(authlist);
	return r;
}

/* ARGSUSED */
int
input_userauth_pk_ok(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct sshkey *key = NULL;
	struct sshbuf *b = NULL;
	struct identity *id = NULL;
	int pktype, sent = 0;
	size_t alen, blen;
	char *pkalg = NULL, *fp;
	u_char *pkblob = NULL;
	int r;

	if (authctxt == NULL)
		fatal("input_userauth_pk_ok: no authentication context");
	if (ssh->compat & SSH_BUG_PKOK) {

		/* this is similar to SSH_BUG_PKAUTH */
		debug2("input_userauth_pk_ok: SSH_BUG_PKOK");
		if ((r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0)
			goto done;
		if ((b = sshbuf_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto done;
		}
		if ((r = sshbuf_put(b, pkblob, blen)) != 0 ||
		    (r = sshbuf_get_cstring(b, &pkalg, NULL)) != 0)
			goto done;
	} else {
		if ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
		    (r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0)
			goto done;
	}
	if ((r = sshpkt_get_end(ssh)) != 0)
		goto done;

	debug("Server accepts key: pkalg %s blen %zu", pkalg, blen);

	if ((pktype = sshkey_type_from_name(pkalg)) == KEY_UNSPEC) {
		debug("unknown pkalg %s", pkalg);
		goto done;
	}
	if ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
		debug("no key from blob. pkalg %s: %s", pkalg, ssh_err(r));
		goto done;
	}
	if (key->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    key->type, pktype);
		goto done;
	}
	fp = sshkey_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
	debug2("input_userauth_pk_ok: fp %s", fp);
	free(fp);

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->keys, idlist, next) {
		if (sshkey_equal(key, id->key)) {
			sent = sign_and_send_pubkey(ssh, id);
			break;
		}
	}
	r = 0;
 done:
	if (key != NULL)
		sshkey_free(key);
	if (b != NULL)
		sshbuf_free(b);
	free(pkalg);
	free(pkblob);

	/* try another method if we did not send a packet */
	if (r == 0 && sent == 0)
		userauth(ssh, NULL);
	return r;
}

#ifdef GSSAPI
int
userauth_gssapi(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = NULL;
	gss_OID oid = NULL;
	OM_uint32 min;
	int r, ok = 0;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	if (authctxt->gss_supported == NULL)
		gss_indicate_mechs(&min, &authctxt->gss_supported);

	/* Check to see if the mechanism is usable before we offer it */
	while (authctxt->gss_mech < authctxt->gss_supported->count && !ok) {
		/* My DER encoding requires length<128 */
		oid = &authctxt->gss_supported->elements[authctxt->gss_mech];
		if (oid->length < 128 &&
		    ssh_gssapi_check_mechanism(&gssctxt, oid, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} else {
			authctxt->gss_mech++;
		}
	}

	if (!ok)
		return 0;

	authctxt->methoddata=(void *)gssctxt;

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, oid->length + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, oid->length)) != 0 ||
	    (r = sshpkt_put(ssh, oid->elements, oid->length)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_RESPONSE, &input_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERROR, &input_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_gssapi_errtok);

	authctxt->gss_mech++; /* Move along to next candidate */

	return 1;
}

static OM_uint32
process_gssapi_token(struct ssh *ssh, gss_buffer_t recv_tok)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	int r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	if (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_MSG_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_MSG_USERAUTH_GSSAPI_TOKEN;

		if ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.value,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));

		gss_release_buffer(&ms, &send_tok);
	}

	if (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		if (!(flags & GSS_C_INTEG_FLAG)) {
			if ((r = sshpkt_start(ssh,
			    SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal("%s: %s", __func__, ssh_err(r));
		} else {
			struct sshbuf *b;

			if ((b = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic");

			if ((gssbuf.value = sshbuf_mutable_ptr(b)) == NULL)
				fatal("%s: sshbuf_mutable_ptr failed", __func__);
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			if (!GSS_ERROR(status)) {
				if ((r = sshpkt_start(ssh,
				    SSH2_MSG_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.value,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal("%s: %s", __func__, ssh_err(r));
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	return status;
}

/* ARGSUSED */
int
input_gssapi_response(int type, u_int32_t plen, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = NULL;
	int r;

	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	if ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		goto out;

	if (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, NULL);
		goto out;
	}

	if (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	if ((r = sshpkt_get_end(ssh)) != 0)
		goto out;

	if (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, NULL);
	}
	r = 0;
 out:
	free(oidv);
	return r;
}

/* ARGSUSED */
int
input_gssapi_token(int type, u_int32_t plen, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = NULL;
	size_t len;
	OM_uint32 status;
	int r;

	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");

	if ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	recv_tok.value = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	if (GSS_ERROR(status))
		userauth(ssh, NULL);
	r = 0;
 out:
	free(p);
	return r;
}

/* ARGSUSED */
int
input_gssapi_errtok(int type, u_int32_t plen, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p;
	size_t len;
	int r;

	if (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	if ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	/* Stick it into GSSAPI and see what it says */
	recv_tok.value = p;
	recv_tok.length = len;
	(void)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, NULL);
	r = 0;
 out:
	free(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	return r;
}

/* ARGSUSED */
int
input_gssapi_error(int type, u_int32_t plen, struct ssh *ssh)
{
	char *msg = NULL;
	char *lang = NULL;
	int r;

	if ((r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &msg, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
		goto out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", msg);
 out:
	free(msg);
	free(lang);
	return r;
}
#endif /* GSSAPI */

int
userauth_none(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	int r;

	/* initial userauth request */
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	return 1;
}

int
userauth_passwd(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	char prompt[150];
	char *password;
	const char *host = options.host_key_alias ?  options.host_key_alias :
	    authctxt->host;
	int r;

	if (authctxt->attempt++ >= options.number_of_password_prompts)
		return 0;

	if (authctxt->attempt != 1)
		error("Permission denied, please try again.");

	snprintf(prompt, sizeof(prompt), "%.30s@%.128s's password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	if (password) {
		memset(password, 0, strlen(password));
		free(password);
	}

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);

	return 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
/* ARGSUSED */
int
input_userauth_passwd_changereq(int type, u_int32_t seqnr, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	char *info = NULL, *lang = NULL, *password = NULL, *retype = NULL;
	char prompt[150];
	const char *host = options.host_key_alias ? options.host_key_alias :
	    authctxt->host;
	int r;

	debug2("input_userauth_passwd_changereq");

	if (authctxt == NULL)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");

	if ((r = sshpkt_get_cstring(ssh, &info, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
		goto out;
	if (strlen(info) > 0)
		logit("%s", info);
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		goto out;

	snprintf(prompt, sizeof(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	if ((r = sshpkt_put_cstring(ssh, password)) != 0)
		goto out;

	memset(password, 0, strlen(password));
	free(password);
	password = NULL;

	while (password == NULL) {
		snprintf(prompt, sizeof(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		if (password == NULL) {
			/* bail out */
			r = 0;
			goto out;
		}
		snprintf(prompt, sizeof(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		if (strcmp(password, retype) != 0) {
			memset(password, 0, strlen(password));
			free(password);
			logit("Mismatch; try again, EOF to quit.");
			password = NULL;
		}
		memset(retype, 0, strlen(retype));
		free(retype);
	}
	if ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);
	r = 0;
 out:
	if (password) {
		memset(password, 0, strlen(password));
		free(password);
	}
	free(info);
	free(lang);
	return r;
}

#ifdef JPAKE
static char *
pw_encrypt(const char *password, const char *crypt_scheme, const char *salt)
{
	/* OpenBSD crypt(3) handles all of these */
	if (strcmp(crypt_scheme, "crypt") == 0 ||
	    strcmp(crypt_scheme, "bcrypt") == 0 ||
	    strcmp(crypt_scheme, "md5crypt") == 0 ||
	    strcmp(crypt_scheme, "crypt-extended") == 0)
		return xstrdup(crypt(password, salt));
	error("%s: unsupported password encryption scheme \"%.100s\"",
	    __func__, crypt_scheme);
	return NULL;
}

static BIGNUM *
jpake_password_to_secret(struct cauthctxt *authctxt, const char *crypt_scheme,
    const char *salt)
{
	char prompt[256], *password, *crypted;
	u_char *secret;
	u_int secret_len;
	BIGNUM *ret;

	snprintf(prompt, sizeof(prompt), "%.30s@%.128s's password (JPAKE): ",
	    authctxt->server_user, authctxt->host);
	password = read_passphrase(prompt, 0);

	if ((crypted = pw_encrypt(password, crypt_scheme, salt)) == NULL) {
		logit("Disabling %s authentication", authctxt->method->name);
		authctxt->method->enabled = NULL;
		/* Continue with an empty password to fail gracefully */
		crypted = xstrdup("");
	}

#ifdef JPAKE_DEBUG
	debug3("%s: salt = %s", __func__, salt);
	debug3("%s: scheme = %s", __func__, crypt_scheme);
	debug3("%s: crypted = %s", __func__, crypted);
#endif

	if (hash_buffer(crypted, strlen(crypted), EVP_sha256(),
	    &secret, &secret_len) != 0)
		fatal("%s: hash_buffer", __func__);

	bzero(password, strlen(password));
	bzero(crypted, strlen(crypted));
	free(password);
	free(crypted);

	if ((ret = BN_bin2bn(secret, secret_len, NULL)) == NULL)
		fatal("%s: BN_bin2bn (secret)", __func__);
	bzero(secret, secret_len);
	free(secret);

	return ret;
}

/* ARGSUSED */
int
input_userauth_jpake_server_step1(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct jpake_ctx *pctx = authctxt->methoddata;
	u_char *x3_proof = NULL, *x4_proof = NULL, *x2_s_proof = NULL;
	size_t x3_proof_len, x4_proof_len, len;
	u_int x2_s_proof_len;
	char *crypt_scheme, *salt;
	int r;

	/* Disable this message */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP1, NULL);

	if ((pctx->g_x3 = BN_new()) == NULL ||
	    (pctx->g_x4 = BN_new()) == NULL)
		fatal("%s: BN_new", __func__);

	/* Fetch step 1 values */
	if ((r = sshpkt_get_cstring(ssh, &crypt_scheme, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &salt, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, &pctx->server_id, &len)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, pctx->g_x3)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, pctx->g_x4)) != 0 ||
	    (r = sshpkt_get_string(ssh, &x3_proof, &x3_proof_len)) != 0 ||
	    (r = sshpkt_get_string(ssh, &x4_proof, &x4_proof_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	pctx->server_id_len = len

	JPAKE_DEBUG_CTX((pctx, "step 1 received in %s", __func__));

	/* Obtain password and derive secret */
	pctx->s = jpake_password_to_secret(authctxt, crypt_scheme, salt);
	bzero(crypt_scheme, strlen(crypt_scheme));
	bzero(salt, strlen(salt));
	free(crypt_scheme);
	free(salt);

	JPAKE_DEBUG_BN((pctx->s, "%s: s = ", __func__));

	/* Calculate step 2 values */
	jpake_step2(pctx->grp, pctx->s, pctx->g_x1,
	    pctx->g_x3, pctx->g_x4, pctx->x2,
	    pctx->server_id, pctx->server_id_len,
	    pctx->client_id, pctx->client_id_len,
	    x3_proof, x3_proof_len,
	    x4_proof, x4_proof_len,
	    &pctx->a,
	    &x2_s_proof, &x2_s_proof_len);

	JPAKE_DEBUG_CTX((pctx, "step 2 sending in %s", __func__));

	/* Send values for step 2 */
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_JPAKE_CLIENT_STEP2)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pctx->a)) != 0 ||
	    (r = sshpkt_put_string(ssh, x2_s_proof, x2_s_proof_len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	/* Expect step 2 packet from peer */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP2,
	    input_userauth_jpake_server_step2);
	r = 0;
 out:
	if (x2_s_proof) {
		bzero(x2_s_proof, x2_s_proof_len);
		free(x2_s_proof);
	}
	if (x3_proof) {
		bzero(x3_proof, x3_proof_len);
		free(x3_proof);
	}
	if (x4_proof) {
		bzero(x4_proof, x4_proof_len);
		free(x4_proof);
	}
	if (crypt_scheme) {
		bzero(crypt_scheme, strlen(crypt_scheme));
		free(crypt_scheme);
	}
	if (salt) {
		bzero(salt, strlen(salt));
		free(salt);
	}
	if (r != 0)
		userauth_jpake_cleanup(ssh);
	return r;
}

/* ARGSUSED */
int
input_userauth_jpake_server_step2(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct jpake_ctx *pctx = authctxt->methoddata;
	u_char *x4_s_proof = NULL;
	size_t x4_s_proof_len;
	int r;

	/* Disable this message */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP2, NULL);

	if ((pctx->b = BN_new()) == NULL)
		fatal("%s: BN_new", __func__);

	/* Fetch step 2 values */
	if ((r = sshpkt_get_bignum2(ssh, pctx->b)) != 0 ||
	    (r = sshpkt_get_string(ssh, &x4_s_proof, &x4_s_proof_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	JPAKE_DEBUG_CTX((pctx, "step 2 received in %s", __func__));

	/* Derive shared key and calculate confirmation hash */
	jpake_key_confirm(pctx->grp, pctx->s, pctx->b,
	    pctx->x2, pctx->g_x1, pctx->g_x2, pctx->g_x3, pctx->g_x4,
	    pctx->client_id, pctx->client_id_len,
	    pctx->server_id, pctx->server_id_len,
	    ssh->kex->session_id, ssh->kex->session_id_len,
	    x4_s_proof, x4_s_proof_len,
	    &pctx->k,
	    &pctx->h_k_cid_sessid, &pctx->h_k_cid_sessid_len);

	JPAKE_DEBUG_CTX((pctx, "confirm sending in %s", __func__));

	/* Send key confirmation proof */
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_JPAKE_CLIENT_CONFIRM)) != 0 ||
	    (r = sshpkt_put_string(ssh, pctx->h_k_cid_sessid,
	    pctx->h_k_cid_sessid_len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	/* Expect confirmation from peer */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_JPAKE_SERVER_CONFIRM,
	    input_userauth_jpake_server_confirm);
	r = 0;
 out:
	if (x4_s_proof) {
		bzero(x4_s_proof, x4_s_proof_len);
		free(x4_s_proof);
	}
	if (r != 0)
		userauth_jpake_cleanup(ssh);
	return r;
}

/* ARGSUSED */
int
input_userauth_jpake_server_confirm(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct jpake_ctx *pctx = authctxt->methoddata;
	size_t len;
	int r;

	/* Disable this message */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_JPAKE_SERVER_CONFIRM, NULL);

	if ((r = sshpkt_get_string(ssh, &pctx->h_k_sid_sessid, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	pctx->h_k_sid_sessid_len = len;

	JPAKE_DEBUG_CTX((pctx, "confirm received in %s", __func__));

	/* Verify expected confirmation hash */
	if (jpake_check_confirm(pctx->k,
	    pctx->server_id, pctx->server_id_len,
	    ssh->kex->session_id, ssh->kex->session_id_len,
	    pctx->h_k_sid_sessid, pctx->h_k_sid_sessid_len) == 1)
		debug("%s: %s success", __func__, authctxt->method->name);
	else {
		debug("%s: confirmation mismatch", __func__);
		/* XXX stash this so if auth succeeds then we can warn/kill */
	}

 out:
	userauth_jpake_cleanup(ssh);
	return r;
}
#endif /* JPAKE */

static int
identity_sign(struct identity *id, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	struct sshkey *prv;
	int ret;

	/* the agent supports this key */
	if (id->agent_fd)
		return ssh_agent_sign(id->agent_fd, id->key, sigp, lenp,
		    data, datalen, compat);
	/*
	 * we have already loaded the private key or
	 * the private key is stored in external hardware
	 */
	if (id->isprivate || (id->key->flags & SSHKEY_FLAG_EXT))
		return (sshkey_sign(id->key, sigp, lenp, data, datalen,
		    compat));
	/* load the private key from the file */
	if ((prv = load_identity_file(id->filename, id->userprovided)) == NULL)
		return (-1); /* XXX return decent error code */
	ret = sshkey_sign(prv, sigp, lenp, data, datalen, compat);
	sshkey_free(prv);
	return (ret);
}

static int
sign_and_send_pubkey(struct ssh *ssh, struct identity *id)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct sshbuf *b;
	u_char *blob, *signature;
	size_t bloblen, slen, skip = 0;
	int r, ret = -1;
	int have_sig = 1;
	char *fp;

	fp = sshkey_fingerprint(id->key, SSH_FP_MD5, SSH_FP_HEX);
	debug3("%s: %s %s", __func__, sshkey_type(id->key), fp);
	free(fp);

	if ((r = sshkey_to_blob(id->key, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3("%s: cannot handle key: %s", __func__, ssh_err(r));
		return 0;
	}
	/* data to be signed */
	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if (ssh->compat & SSH_OLD_SESSIONID) {
		if ((r = sshbuf_put(b, ssh->kex->session_id,
		    ssh->kex->session_id_len)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		skip = ssh->kex->session_id_len;
	} else {
		if ((r = sshbuf_put_string(b, ssh->kex->session_id,
		    ssh->kex->session_id_len)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		skip = sshbuf_len(b);
	}
	if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, ssh->compat & SSH_BUG_PKSERVICE ?
	    "ssh-userauth" : authctxt->service)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (ssh->compat & SSH_BUG_PKAUTH) {
		if ((r = sshbuf_put_u8(b, have_sig)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	} else {
		if ((r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, sshkey_ssh_name(id->key))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	if ((r = sshbuf_put_string(b, blob, bloblen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* generate signature */
	if ((ret = identity_sign(id, &signature, &slen,
	    sshbuf_ptr(b), sshbuf_len(b), ssh->compat)) != 0) {
		error("signature failed: %s", ssh_err(ret));
		free(blob);
		sshbuf_free(b);
		return 0;
	}
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	if (ssh->compat & SSH_BUG_PKSERVICE) {
		sshbuf_reset(b);
		if ((r = sshbuf_put(b, ssh->kex->session_id,
		    ssh->kex->session_id_len)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		skip = ssh->kex->session_id_len;
		if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		if (!(ssh->compat & SSH_BUG_PKAUTH))
			if ((r = sshbuf_put_cstring(b,
			    sshkey_ssh_name(id->key))) != 0 ||
			    (r = sshbuf_put_string(b, blob, bloblen)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	free(blob);

	/* append signature */
	if ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	free(signature);

	/* skip session id and packet type */
	if (sshbuf_len(b) < skip + 1)
		fatal("%s: internal error", __func__);
	if ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* put remaining data from buffer into packet */
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put(ssh, sshbuf_ptr(b), sshbuf_len(b))) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: send error: %s", __func__, ssh_err(r));
	sshbuf_free(b);

	return 1;
}

static int
send_pubkey_test(struct ssh *ssh, struct identity *id)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	u_char *blob;
	size_t bloblen;
	u_int have_sig = 0;
	int r;

	debug3("send_pubkey_test");

	if ((r = sshkey_to_blob(id->key, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3("%s: cannot handle key: %s", __func__, ssh_err(r));
		return 0;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PK_OK, &input_userauth_pk_ok);

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (!(ssh->compat & SSH_BUG_PKAUTH) &&
	    (r = sshpkt_put_cstring(ssh, sshkey_ssh_name(id->key))) != 0) ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	free(blob);
	return 1;
}

/* XXX merge with key loading from sshconnect1.c */
static struct sshkey *
load_identity_file(char *filename, int userprovided)
{
	struct sshkey *private = NULL;
	char prompt[300], *passphrase;
	int r, perm_ok = 0, quit, i;
	struct stat st;

	if (stat(filename, &st) < 0) {
		(userprovided ? logit : debug3)("no such identity: %s: %s",
		    filename, strerror(errno));
		return NULL;
	}
	snprintf(prompt, sizeof prompt,
	    "Enter passphrase for key '%.100s': ", filename);
	for (i = 0; i <= options.number_of_password_prompts; i++) {
		if (i == 0)
			passphrase = "";
		else {
			passphrase = read_passphrase(prompt, 0);
			if (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				free(passphrase);
				break;
			}
		}
		switch ((r = sshkey_load_private_type(KEY_UNSPEC, filename,
		    passphrase, &private, NULL, &perm_ok))) {
		case 0:
			break;
		case SSH_ERR_KEY_WRONG_PASSPHRASE:
			if (options.batch_mode) {
				quit = 1;
				break;
			}
			debug2("bad passphrase given, try again...");
			break;
		case SSH_ERR_SYSTEM_ERROR:
			if (errno == ENOENT) {
				debug2("Load key \"%s\": %s",
				    filename, ssh_err(r));
				quit = 1;
				break;
			}
			/* FALLTHROUGH */
		default:
			error("Load key \"%s\": %s", filename, ssh_err(r));
			quit = 1;
			break;
		}
		if (i > 0) {
			memset(passphrase, 0, strlen(passphrase));
			free(passphrase);
		}
		if (private != NULL || quit)
			break;
	}
	return private;
}

/*
 * try keys in the following order:
 *	1. agent keys that are found in the config file
 *	2. other agent keys
 *	3. keys that are only listed in the config file
 */
static void
pubkey_prepare(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct identity *id, *id2, *tmp;
	struct idlist agent, files, *preferred;
	struct sshkey *key;
	int agent_fd, i, r, found;
	size_t j;
	struct ssh_identitylist *idlist;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	preferred = &authctxt->keys;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	for (i = 0; i < options.num_identity_files; i++) {
		key = options.identity_keys[i];
		if (key && key->type == KEY_RSA1)
			continue;
		if (key && key->cert && key->cert->type != SSH2_CERT_TYPE_USER)
			continue;
		options.identity_keys[i] = NULL;
		id = xcalloc(1, sizeof(*id));
		id->key = key;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		if (id->key == NULL || (id->key->flags & SSHKEY_FLAG_EXT) == 0)
			continue;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			if (id2->key == NULL ||
			    (id2->key->flags & SSHKEY_FLAG_EXT) != 0)
				continue;
			if (sshkey_equal(id->key, id2->key)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				break;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		if (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			bzero(id, sizeof(*id));
			free(id);
		}
	}
	/* list of keys supported by the agent */
	if ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		if (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug("%s: ssh_get_authentication_socket: %s",
			    __func__, ssh_err(r));
	} else if ((r = ssh_fetch_identitylist(agent_fd, 2, &idlist)) != 0) {
		if (r != SSH_ERR_AGENT_NO_IDENTITIES)
			debug("%s: ssh_fetch_identitylist: %s",
			    __func__, ssh_err(r));
	} else {
		for (j = 0; j < idlist->nkeys; j++) {
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				if (sshkey_equal(idlist->keys[j], id->key)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(preferred, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					break;
				}
			}
			if (!found && !options.identities_only) {
				id = xcalloc(1, sizeof(*id));
				/* XXX "steals" key/comment from idlist */
				id->key = idlist->keys[j];
				id->filename = idlist->comments[j];
				idlist->keys[j] = NULL;
				idlist->comments[j] = NULL;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		for (id = TAILQ_FIRST(&agent); id; id = TAILQ_FIRST(&agent)) {
			TAILQ_REMOVE(&agent, id, next);
			TAILQ_INSERT_TAIL(preferred, id, next);
		}
		authctxt->agent_fd = agent_fd;
	}
	/* append remaining keys from the config file */
	for (id = TAILQ_FIRST(&files); id; id = TAILQ_FIRST(&files)) {
		TAILQ_REMOVE(&files, id, next);
		TAILQ_INSERT_TAIL(preferred, id, next);
	}
	TAILQ_FOREACH(id, preferred, next) {
		debug2("key: %s (%p),%s", id->filename, id->key,
		    id->userprovided ? " explicit" : "");
	}
}

static void
pubkey_cleanup(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct identity *id;

	if (authctxt->agent_fd != -1)
		ssh_close_authentication_socket(authctxt->agent_fd);
	for (id = TAILQ_FIRST(&authctxt->keys); id;
	    id = TAILQ_FIRST(&authctxt->keys)) {
		TAILQ_REMOVE(&authctxt->keys, id, next);
		if (id->key)
			sshkey_free(id->key);
		free(id->filename);
		free(id);
	}
}

int
userauth_pubkey(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct identity *id;
	int sent = 0;

	while ((id = TAILQ_FIRST(&authctxt->keys))) {
		if (id->tried++)
			return (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->keys, id, next);
		TAILQ_INSERT_TAIL(&authctxt->keys, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		if (id->key && id->key->type != KEY_RSA1) {
			debug("Offering %s public key: %s",
			    sshkey_type(id->key), id->filename);
			sent = send_pubkey_test(ssh, id);
		} else if (id->key == NULL) {
			debug("Trying private key: %s", id->filename);
			id->key = load_identity_file(id->filename,
			    id->userprovided);
			if (id->key != NULL) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->key);
				id->key = NULL;
			}
		}
		if (sent)
			return (sent);
	}
	return (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
int
userauth_kbdint(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	int r;

	if (authctxt->attempt++ >= options.number_of_password_prompts)
		return 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	if (authctxt->attempt > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST, NULL);
		return 0;
	}

	debug2("userauth_kbdint");
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST, &input_userauth_info_req);
	return 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
int
input_userauth_info_req(int type, u_int32_t seq, struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	char *name = NULL, *inst = NULL, *lang = NULL, *prompt = NULL;
	char *response = NULL;
	u_char echo = 0;
	u_int num_prompts, i;
	int r;

	debug2("input_userauth_info_req");

	if (authctxt == NULL)
		fatal("input_userauth_info_req: no authentication context");

	authctxt->info_req_seen = 1;

	if ((r = sshpkt_get_cstring(ssh, &name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
		goto out;
	if (strlen(name) > 0)
		logit("%s", name);
	if (strlen(inst) > 0)
		logit("%s", inst);

	if ((r = sshpkt_get_u32(ssh, &num_prompts)) != 0)
		goto out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, num_prompts)) != 0)
		goto out;

	debug2("input_userauth_info_req: num_prompts %d", num_prompts);
	for (i = 0; i < num_prompts; i++) {
		if ((r = sshpkt_get_cstring(ssh, &prompt, NULL)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			goto out;
		response = read_passphrase(prompt, echo ? RP_ECHO : 0);
		if ((r = sshpkt_put_cstring(ssh, response)) != 0)
			goto out;
		memset(response, 0, strlen(response));
		free(response);
		free(prompt);
		response = prompt = NULL;
	}
	/* done with parsing incoming message. */
	if ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		goto out;
	r = sshpkt_send(ssh);
 out:
	if (response) {
		memset(response, 0, strlen(response));
		free(response);
	}
	free(prompt);
	free(name);
	free(inst);
	free(lang);
	return r;
}

static int
ssh_keysign(struct ssh *ssh, struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	struct sshbuf *b;
	struct stat st;
	pid_t pid;
	int r, to[2], from[2], status;
	u_char rversion, version = 2;
	size_t len;

	debug2("%s called", __func__);

	if (stat(_PATH_SSH_KEY_SIGN, &st) < 0) {
		error("%s: not installed: %s", __func__, strerror(errno));
		return -1;
	}
	if (fflush(stdout) != 0)
		error("%s: fflush: %s", __func__, strerror(errno));
	if (pipe(to) < 0) {
		error("%s: pipe: %s", __func__, strerror(errno));
		return -1;
	}
	if (pipe(from) < 0) {
		error("%s: pipe: %s", __func__, strerror(errno));
		return -1;
	}
	if ((pid = fork()) < 0) {
		error("%s: fork: %s", __func__, strerror(errno));
		return -1;
	}
	if (pid == 0) {
		/* keep the socket on exec */
		fcntl(ssh_packet_get_connection_in(ssh), F_SETFD, 0);
		permanently_drop_suid(getuid());
		close(from[0]);
		if (dup2(from[1], STDOUT_FILENO) < 0)
			fatal("%s: dup2: %s", __func__, strerror(errno));
		close(to[1]);
		if (dup2(to[0], STDIN_FILENO) < 0)
			fatal("%s: dup2: %s", __func__, strerror(errno));
		close(from[1]);
		close(to[0]);
		execl(_PATH_SSH_KEY_SIGN, _PATH_SSH_KEY_SIGN, (char *) 0);
		fatal("%s: exec(%s): %s", __func__, _PATH_SSH_KEY_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	/* send # of socket */
	if ((r = sshbuf_put_u32(b, ssh_packet_get_connection_in(ssh))) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (ssh_msg_send(to[1], version, b) == -1)
		fatal("%s: couldn't send request", __func__);

	sshbuf_reset(b);

	if (ssh_msg_recv(from[0], b) < 0) {
		error("%s: no reply", __func__);
		sshbuf_free(b);
		return -1;
	}
	close(from[0]);
	close(to[1]);

	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			break;
	if ((r = sshbuf_get_u8(b, &rversion)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (rversion != version) {
		error("%s: bad version", __func__);
		sshbuf_free(b);
		return -1;
	}
	if ((r = sshbuf_get_string(b, sigp, &len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	*lenp = len; /* XXX */
	sshbuf_free(b);

	return 0;
}

int
userauth_hostbased(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct sshkey *private = NULL;
	Sensitive *sensitive = authctxt->sensitive;
	struct sshbuf *b;
	u_char *signature, *blob;
	char *chost, *pkalg, *p;
	const char *service;
	size_t blen, slen;
	int ok, i, r, found = 0;

	/* check for a useful key */
	for (i = 0; i < sensitive->nkeys; i++) {
		private = sensitive->keys[i];
		if (private && private->type != KEY_RSA1) {
			found = 1;
			/* we take and free the key */
			sensitive->keys[i] = NULL;
			break;
		}
	}
	if (!found) {
		debug("No more client hostkeys for hostbased authentication.");
		return 0;
	}
	if ((ok = sshkey_to_blob(private, &blob, &blen)) != 0) {
		error("%s: sshkey_to_blob failed: %s", __func__, ssh_err(ok));
		sshkey_free(private);
		return 0;
	}
	/* figure out a name for the client host */
	p = get_local_name(ssh_packet_get_connection_in(ssh));
	if (p == NULL) {
		error("userauth_hostbased: cannot get local ipaddr/name");
		sshkey_free(private);
		free(blob);
		return 0;
	}
	xasprintf(&chost, "%s.", p);
	debug2("userauth_hostbased: chost %s", chost);
	free(p);

	service = ssh->compat & SSH_BUG_HBSERVICE ? "ssh-userauth" :
	    authctxt->service;
	pkalg = xstrdup(sshkey_ssh_name(private));
	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	/* construct data */
	if ((r = sshbuf_put_string(b, ssh->kex->session_id,
	    ssh->kex->session_id_len)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
	    (r = sshbuf_put_string(b, blob, blen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	if (sensitive->external_keysign)
		ok = ssh_keysign(ssh, private, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b));
	else
		ok = sshkey_sign(private, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat);
	sshkey_free(private);
	sshbuf_free(b);
	if (ok != 0) {
		error("sshkey_sign failed");
		free(chost);
		free(pkalg);
		free(blob);
		return 0;
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, blen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	memset(signature, 's', slen);
	free(signature);
	free(chost);
	free(pkalg);
	free(blob);

	return 1;
}

#ifdef JPAKE
int
userauth_jpake(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	struct jpake_ctx *pctx;
	u_char *x1_proof, *x2_proof;
	u_int x1_proof_len, x2_proof_len;
	int r;

	if (authctxt->attempt++ >= options.number_of_password_prompts)
		return 0;
	if (authctxt->attempt != 1)
		error("Permission denied, please try again.");

	if (authctxt->methoddata != NULL)
		fatal("%s: authctxt->methoddata already set (%p)",
		    __func__, authctxt->methoddata);

	authctxt->methoddata = pctx = jpake_new();

	/*
	 * Send request immediately, to get the protocol going while
	 * we do the initial computations.
	 */
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	ssh_packet_write_wait(ssh);

	jpake_step1(pctx->grp,
	    &pctx->client_id, &pctx->client_id_len,
	    &pctx->x1, &pctx->x2, &pctx->g_x1, &pctx->g_x2,
	    &x1_proof, &x1_proof_len,
	    &x2_proof, &x2_proof_len);

	JPAKE_DEBUG_CTX((pctx, "step 1 sending in %s", __func__));

	if ((r = sshpkt_start(ssh,
	    SSH2_MSG_USERAUTH_JPAKE_CLIENT_STEP1)) != 0 ||
	    (r = sshpkt_put_string(ssh, pctx->client_id,
	    pctx->client_id_len)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pctx->g_x1)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pctx->g_x2)) != 0 ||
	    (r = sshpkt_put_string(ssh, x1_proof, x1_proof_len)) != 0 ||
	    (r = sshpkt_put_string(ssh, x2_proof, x2_proof_len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	bzero(x1_proof, x1_proof_len);
	bzero(x2_proof, x2_proof_len);
	free(x1_proof);
	free(x2_proof);

	/* Expect step 1 packet from peer */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP1,
	    input_userauth_jpake_server_step1);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_SUCCESS,
	    &input_userauth_success_unexpected);

	return 1;
}

void
userauth_jpake_cleanup(struct ssh *ssh)
{
	struct cauthctxt *authctxt = ssh->authctxt;
	debug3("%s: clean up", __func__);
	if (authctxt->methoddata != NULL) {
		jpake_free(authctxt->methoddata);
		authctxt->methoddata = NULL;
	}
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
}
#endif /* JPAKE */

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
static int
authmethod_is_enabled(struct cauthmethod *method)
{
	if (method == NULL)
		return 0;
	/* return false if options indicate this method is disabled */
	if  (method->enabled == NULL || *method->enabled == 0)
		return 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	if  (method->batch_flag != NULL && *method->batch_flag != 0)
		return 0;
	return 1;
}

static struct cauthmethod *
authmethod_lookup(const char *name)
{
	struct cauthmethod *method = NULL;
	if (name != NULL)
		for (method = authmethods; method->name != NULL; method++)
			if (strcmp(name, method->name) == 0)
				return method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	return NULL;
}

/* XXX internal state */
static struct cauthmethod *current = NULL;
static char *supported = NULL;
static char *preferred = NULL;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
static struct cauthmethod *
authmethod_get(char *authlist)
{
	char *name = NULL;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	if (authlist == NULL || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	if (supported == NULL || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		free(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = NULL;
	} else if (current != NULL && authmethod_is_enabled(current))
		return current;

	for (;;) {
		if ((name = match_list(preferred, supported, &next)) == NULL) {
			debug("No more authentication methods to try.");
			current = NULL;
			return NULL;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		if ((current = authmethod_lookup(name)) != NULL &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			free(name);
			return current;
		}
		free(name);
	}
}

static char *
authmethods_get(void)
{
	struct cauthmethod *method = NULL;
	struct sshbuf *b;
	char *list;
	int r;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	for (method = authmethods; method->name != NULL; method++) {
		if (authmethod_is_enabled(method)) {
			if ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
	}
	if ((r = sshbuf_put_u8(b, 0)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	list = xstrdup((const char *)sshbuf_ptr(b));
	sshbuf_free(b);
	return list;
}
