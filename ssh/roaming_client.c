/* $OpenBSD: roaming_client.c,v 1.5 2013/05/17 00:13:14 djm Exp $ */
/*
 * Copyright (c) 2004-2009 AppGate Network Security AB
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "err.h"
#include "channels.h"
#include "cipher.h"
#include "dispatch.h"
#include "clientloop.h"
#include "log.h"
#include "match.h"
#include "misc.h"
#include "packet.h"
#include "ssh.h"
#include "key.h"
#include "kex.h"
#include "readconf.h"
#include "roaming.h"
#include "ssh2.h"
#include "sshconnect.h"
#include "err.h"

/* import */
extern Options options;
extern char *host;
extern struct sockaddr_storage hostaddr;
extern int session_resumed;

static u_int32_t roaming_id;
static u_int64_t cookie;
static u_int64_t lastseenchall;
static u_int64_t key1, key2, oldkey1, oldkey2;

void
roaming_reply(struct ssh *ssh, int type, u_int32_t seq, void *ctxt)
{
	u_int size;
	int r;

	if (type == SSH2_MSG_REQUEST_FAILURE) {
		logit("Server denied roaming");
		return;
	}
	verbose("Roaming enabled");
	if ((r = sshpkt_get_u32(ssh, &roaming_id)) != 0 ||
	    (r = sshpkt_get_u64(ssh, &cookie)) != 0 ||
	    (r = sshpkt_get_u64(ssh, &oldkey1)) != 0 ||
	    (r = sshpkt_get_u64(ssh, &oldkey2)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &size)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	key1 = oldkey1;
	key2 = oldkey2;
	set_out_buffer_size(size + get_snd_buf_size(ssh));
	roaming_enabled = 1;
}

void
request_roaming(struct ssh *ssh)
{
	int r;

	if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ROAMING_REQUEST)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, get_recv_buf_size(ssh))) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	client_register_global_confirm(roaming_reply, NULL);
}

static void
roaming_auth_required(struct ssh *ssh)
{
	u_char digest[SHA_DIGEST_LENGTH];
	EVP_MD_CTX md;
	struct sshbuf *b;
	const EVP_MD *evp_md = EVP_sha1();
	u_int64_t chall, oldchall;
	int r;

	if ((r = sshpkt_get_u64(ssh, &chall)) != 0 ||
	    (r = sshpkt_get_u64(ssh, &oldchall)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	if (oldchall != lastseenchall) {
		key1 = oldkey1;
		key2 = oldkey2;
	}
	lastseenchall = chall;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u64(b, cookie)) != 0 ||
	    (r = sshbuf_put_u64(b, chall)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, sshbuf_ptr(b), sshbuf_len(b));
	EVP_DigestFinal(&md, digest, NULL);
	sshbuf_free(b);

	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ROAMING_AUTH)) != 0 ||
	    (r = sshpkt_put_u64(ssh, key1 ^ get_recv_bytes())) != 0 ||
	    (r = sshpkt_put(ssh, digest, sizeof(digest))) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	oldkey1 = key1;
	oldkey2 = key2;
	calculate_new_key(&key1, cookie, chall);
	calculate_new_key(&key2, cookie, chall);

	debug("Received %llu bytes", (unsigned long long)get_recv_bytes());
	debug("Sent roaming_auth packet");
}

int
resume_kex(void)
{
	/*
	 * This should not happen - if the client sends the kex method
	 * resume@appgate.com then the kex is done in roaming_resume().
	 */
	return 1;
}

static int
roaming_resume(void)
{
	struct ssh *ssh = active_state;	/* XXX */
	u_int64_t recv_bytes;
	char *str = NULL, *kexlist = NULL, *c;
	int r = 0, i, type;
	int timeout_ms = options.connection_timeout * 1000;
	u_char first_kex_packet_follows, kex_cookie[KEX_COOKIE_LEN];

	resume_in_progress = 1;

	/* Exchange banners */
	ssh_exchange_identification(ssh, timeout_ms);
	ssh_packet_set_nonblocking(ssh);

	/* Send a kexinit message with resume@appgate.com as only kex algo */
	arc4random_buf(kex_cookie, KEX_COOKIE_LEN);
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshpkt_put(ssh, kex_cookie, KEX_COOKIE_LEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, KEX_RESUME)) != 0)
		goto fail;
	for (i = 1; i < PROPOSAL_MAX; i++) {
		/* kex algorithm added so start with i=1 and not 0 */
		/* Not used when we resume */
		if ((r = sshpkt_put_cstring(ssh, "")) != 0)
			goto fail;
	}
	if ((r = sshpkt_put_u8(ssh, 1)) != 0 || /* first kex_packet follows */
	    (r = sshpkt_put_u32(ssh, 0)) != 0 || /* reserved */
	    (r = sshpkt_send(ssh)) != 0)
		goto fail;

	/* Assume that resume@appgate.com will be accepted */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ROAMING_RESUME)) != 0 ||
	    (r = sshpkt_put_u32(ssh, roaming_id)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto fail;

	/* Read the server's kexinit and check for resume@appgate.com */
	if ((type = ssh_packet_read(ssh)) != SSH2_MSG_KEXINIT) {
		debug("expected kexinit on resume, got %d", type);
		goto fail;
	}
	if ((r = sshpkt_get(ssh, NULL, KEX_COOKIE_LEN)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &kexlist, NULL)) != 0)
		goto fail;
	if (!kexlist
	    || (str = match_list(KEX_RESUME, kexlist, NULL)) == NULL) {
		debug("server doesn't allow resume");
		goto fail;
	}
	free(str);
	/* kex algorithm taken care of so start with i=1 and not 0 */
	for (i = 1; i < PROPOSAL_MAX; i++)
		if ((r = sshpkt_get_string(ssh, NULL, NULL)) != 0)
			goto fail;
	if ((r = sshpkt_get_u8(ssh, &first_kex_packet_follows)) != 0)
		goto fail;
	if (first_kex_packet_follows && (c = strchr(kexlist, ',')))
		*c = 0;
	if (first_kex_packet_follows && strcmp(kexlist, KEX_RESUME)) {
		debug("server's kex guess (%s) was wrong, skipping", kexlist);
		ssh_packet_read(ssh); /* Wrong guess - discard packet */
	}

	/*
	 * Read the ROAMING_AUTH_REQUIRED challenge from the server and
	 * send ROAMING_AUTH
	 */
	if ((type = ssh_packet_read(ssh)) != SSH2_MSG_KEX_ROAMING_AUTH_REQUIRED) {
		debug("expected roaming_auth_required, got %d", type);
		goto fail;
	}
	roaming_auth_required(ssh);

	/* Read ROAMING_AUTH_OK from the server */
	if ((type = ssh_packet_read(ssh)) != SSH2_MSG_KEX_ROAMING_AUTH_OK) {
		debug("expected roaming_auth_ok, got %d", type);
		goto fail;
	}
	if ((r = sshpkt_get_u64(ssh, &recv_bytes)) != 0)
		goto fail;
	recv_bytes = recv_bytes ^ oldkey2;

	debug("Peer received %llu bytes", (unsigned long long)recv_bytes);
	resend_bytes(ssh_packet_get_connection_out(ssh), &recv_bytes);

	resume_in_progress = 0;

	session_resumed = 1; /* Tell clientloop */

	return 0;

fail:
	if (r != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	free(kexlist);
	if (ssh_packet_get_connection_in(ssh) ==
	    ssh_packet_get_connection_out(ssh))
		close(ssh_packet_get_connection_in(ssh));
	else {
		close(ssh_packet_get_connection_in(ssh));
		close(ssh_packet_get_connection_out(ssh));
	}
	return 1;
}

int
wait_for_roaming_reconnect(void)
{
	static int reenter_guard = 0;
	struct ssh *nssh;
	int timeout_ms = options.connection_timeout * 1000;
	int c;

	if (reenter_guard != 0)
		fatal("Server refused resume, roaming timeout may be exceeded");
	reenter_guard = 1;

	fprintf(stderr, "[connection suspended, press return to resume]");
	fflush(stderr);
	ssh_packet_backup_state(NULL, NULL);	/* XXX FIXME */
	/* TODO Perhaps we should read from tty here */
	while ((c = fgetc(stdin)) != EOF) {
		if (c == 'Z' - 64) {
			kill(getpid(), SIGTSTP);
			continue;
		}
		if (c != '\n' && c != '\r')
			continue;

		nssh = ssh_connect(host, &hostaddr, options.port,
		    options.address_family, 1, &timeout_ms,
		    options.tcp_keep_alive, options.use_privileged_port,
		    options.proxy_command);
		if (nssh && roaming_resume()) {
			ssh_packet_restore_state(NULL, NULL); /* XXX FIXME */
			reenter_guard = 0;
			fprintf(stderr, "[connection resumed]\n");
			fflush(stderr);
			return 0;
		}

		fprintf(stderr, "[reconnect failed, press return to retry]");
		fflush(stderr);
	}
	fprintf(stderr, "[exiting]\n");
	fflush(stderr);
	exit(0);
}
