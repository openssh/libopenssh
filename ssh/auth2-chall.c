/* $OpenBSD: auth2-chall.c,v 1.38 2013/05/17 00:13:13 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Per Allansson.  All rights reserved.
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

#include <stdio.h>
#include <string.h>

#include "xmalloc.h"
#include "ssh2.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "sshbuf.h"
#include "packet.h"
#include "dispatch.h"
#include "err.h"
#include "log.h"

static int auth2_challenge_start(struct ssh *);
static int send_userauth_info_request(struct ssh *);
static int input_userauth_info_response(int, u_int32_t, struct ssh *);

extern struct kbdintdevice bsdauth_device;

struct kbdintdevice *devices[] = {
	&bsdauth_device,
	NULL
};

struct kbdintctxt {
	char *devices;
	void *ctxt;
	struct kbdintdevice *device;
	u_int nreq;
};

static struct kbdintctxt *
kbdint_alloc(const char *devs)
{
	struct kbdintctxt *kbdintctxt;
	struct sshbuf *b;
	int i, r;

	kbdintctxt = xmalloc(sizeof(struct kbdintctxt));
	if (strcmp(devs, "") == 0) {
		if ((b = sshbuf_new()) == NULL)
			fatal("%s: sshbuf_new failed", __func__);
		for (i = 0; devices[i]; i++) {
			if ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		if ((r = sshbuf_put_u8(b, 0)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		kbdintctxt->devices = xstrdup((const char *)sshbuf_ptr(b));
		sshbuf_free(b);
	} else {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = NULL;
	kbdintctxt->device = NULL;
	kbdintctxt->nreq = 0;

	return kbdintctxt;
}
static void
kbdint_reset_device(struct kbdintctxt *kbdintctxt)
{
	if (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = NULL;
	}
	kbdintctxt->device = NULL;
}
static void
kbdint_free(struct kbdintctxt *kbdintctxt)
{
	if (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	free(kbdintctxt->devices);
	bzero(kbdintctxt, sizeof(*kbdintctxt));
	free(kbdintctxt);
}
/* get next device */
static int
kbdint_next_device(struct authctxt *authctxt, struct kbdintctxt *kbdintctxt)
{
	size_t len;
	char *t;
	int i;

	if (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	do {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		if (len == 0)
			break;
		for (i = 0; devices[i]; i++) {
			if (!auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				continue;
			if (strncmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0)
				kbdintctxt->device = devices[i];
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : NULL;
		free(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} while (kbdintctxt->devices && !kbdintctxt->device);

	return kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
int
auth2_challenge(struct ssh *ssh, char *devs)
{
	struct authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	if (authctxt->user == NULL || !devs)
		return 0;
	if (authctxt->kbdintctxt == NULL)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	return auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
void
auth2_challenge_stop(struct ssh *ssh)
{
	struct authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);
	if (authctxt->kbdintctxt != NULL) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = NULL;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
static int
auth2_challenge_start(struct ssh *ssh)
{
	struct authctxt *authctxt = ssh->authctxt;
	struct kbdintctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	if (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		return 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	if ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == NULL) {
		auth2_challenge_stop(ssh);
		return 0;
	}
	if (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		return 0;
	}
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE,
	    &input_userauth_info_response);

	authctxt->postponed = 1;
	return 0;
}

static int
send_userauth_info_request(struct ssh *ssh)
{
	struct authctxt *authctxt = ssh->authctxt;
	struct kbdintctxt *kbdintctxt = authctxt->kbdintctxt;
	char *name, *instr, **prompts;
	u_int r, i, *echo_on;

	if (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		return 0;

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	for (i = 0; i < kbdintctxt->nreq; i++) {
		if ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
	}
	if ((r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	ssh_packet_write_wait(ssh);

	for (i = 0; i < kbdintctxt->nreq; i++)
		free(prompts[i]);
	free(prompts);
	free(echo_on);
	free(name);
	free(instr);
	return 1;
}

static int
input_userauth_info_response(int type, u_int32_t seq, struct ssh *ssh)
{
	struct authctxt *authctxt = ssh->authctxt;
	struct kbdintctxt *kbdintctxt;
	int authenticated = 0, res;
	int r;
	u_int i, nresp;
	const char *devicename = NULL;
	char **response = NULL;

	if (authctxt == NULL)
		fatal("input_userauth_info_response: no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	if (kbdintctxt == NULL || kbdintctxt->ctxt == NULL)
		fatal("input_userauth_info_response: no kbdintctxt");
	if (kbdintctxt->device == NULL)
		fatal("input_userauth_info_response: no device");

	authctxt->postponed = 0;	/* reset */
	if ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	if (nresp != kbdintctxt->nreq)
		fatal("input_userauth_info_response: wrong number of replies");
	if (nresp > 100)
		fatal("input_userauth_info_response: too many replies");
	if (nresp > 0) {
		response = xcalloc(nresp, sizeof(char *));
		for (i = 0; i < nresp; i++)
			if ((r = sshpkt_get_cstring(ssh, &response[i],
			    NULL)) != 0)
				fatal("%s: %s", __func__, ssh_err(r));
	}
	if ((r = sshpkt_get_end(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	for (i = 0; i < nresp; i++) {
		memset(response[i], 'r', strlen(response[i]));
		free(response[i]);
	}
	free(response);

	switch (res) {
	case 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		break;
	case 1:
		/* Authentication needs further interaction */
		if (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		break;
	default:
		/* Failure! */
		break;
	}
	devicename = kbdintctxt->device->name;
	if (!authctxt->postponed) {
		if (authenticated) {
			auth2_challenge_stop(ssh);
		} else {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	return 0;
}

void
privsep_challenge_enable(void)
{
	extern struct kbdintdevice mm_bsdauth_device;
	/* As long as SSHv1 has devices[0] hard coded this is fine */
	devices[0] = &mm_bsdauth_device;
}
