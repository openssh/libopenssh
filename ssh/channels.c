/* $OpenBSD: channels.c,v 1.324 2013/07/12 00:19:58 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains functions for generic socket connection forwarding.
 * There is also code for initiating connection forwarding for X11 connections,
 * arbitrary tcp/ip connections, and the authentication agent connection.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support added by Markus Friedl.
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 1999 Dug Song.  All rights reserved.
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
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
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "err.h"
#include "ssh.h"
#include "ssh1.h"
#include "ssh2.h"
#include "packet.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "channels.h"
#include "compat.h"
#include "canohost.h"
#include "key.h"
#include "authfd.h"
#include "pathnames.h"

/* -- channel core */

/*
 * Pointer to an array containing all allocated channels.  The array is
 * dynamically extended as needed.
 */
static Channel **channels = NULL;

/*
 * Size of the channel array.  All slots of the array must always be
 * initialized (at least the type field); unused slots set to NULL
 */
static u_int channels_alloc = 0;

/*
 * Maximum file descriptor value used in any of the channels.  This is
 * updated in channel_new.
 */
static int channel_max_fd = 0;


/* -- tcp forwarding */

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
typedef struct {
	char *host_to_connect;		/* Connect to 'host'. */
	u_short port_to_connect;	/* Connect to 'port'. */
	u_short listen_port;		/* Remote side should listen port number. */
} ForwardPermission;

/* List of all permitted host/port pairs to connect by the user. */
static ForwardPermission *permitted_opens = NULL;

/* List of all permitted host/port pairs to connect by the admin. */
static ForwardPermission *permitted_adm_opens = NULL;

/* Number of permitted host/port pairs in the array permitted by the user. */
static int num_permitted_opens = 0;

/* Number of permitted host/port pair in the array permitted by the admin. */
static int num_adm_permitted_opens = 0;

/* special-case port number meaning allow any port */
#define FWD_PERMIT_ANY_PORT	0

/*
 * If this is true, all opens are permitted.  This is the case on the server
 * on which we have to trust the client anyway, and the user could do
 * anything after logging in anyway.
 */
static int all_opens_permitted = 0;


/* -- X11 forwarding */

/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Saved X11 local (client) display. */
static char *x11_saved_display = NULL;

/* Saved X11 authentication protocol name. */
static char *x11_saved_proto = NULL;

/* Saved X11 authentication data.  This is the real data. */
static char *x11_saved_data = NULL;
static u_int x11_saved_data_len = 0;

/*
 * Fake X11 authentication data.  This is what the server will be sending us;
 * we should replace any occurrences of this by the real data.
 */
static u_char *x11_fake_data = NULL;
static u_int x11_fake_data_len;


/* -- agent forwarding */

#define	NUM_SOCKS	10

/* AF_UNSPEC or AF_INET or AF_INET6 */
static int IPv4or6 = AF_UNSPEC;

/* helper */
static void port_open_helper(Channel *c, char *rtype);

/* non-blocking connect helpers */
static int connect_next(struct channel_connect *);
static void channel_connect_ctx_free(struct channel_connect *);

/* -- channel core */

Channel *
channel_by_id(u_int id)
{
	Channel *c;

	if (id >= channels_alloc) {
		logit("channel_by_id: %d: bad id", id);
		return NULL;
	}
	c = channels[id];
	if (c == NULL) {
		logit("channel_by_id: %d: bad id: channel free", id);
		return NULL;
	}
	return c;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(u_int id)
{
	Channel *c;

	if ((c = channel_by_id(id)) == NULL)
		return (NULL);

	switch (c->type) {
	case SSH_CHANNEL_X11_OPEN:
	case SSH_CHANNEL_LARVAL:
	case SSH_CHANNEL_CONNECTING:
	case SSH_CHANNEL_DYNAMIC:
	case SSH_CHANNEL_OPENING:
	case SSH_CHANNEL_OPEN:
	case SSH_CHANNEL_INPUT_DRAINING:
	case SSH_CHANNEL_OUTPUT_DRAINING:
	case SSH_CHANNEL_ABANDONED:
		return (c);
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	return (NULL);
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
static void
channel_register_fds(Channel *c, int rfd, int wfd, int efd,
    int extusage, int nonblock, int is_tty)
{
	/* Update the maximum file descriptor value. */
	channel_max_fd = MAX(channel_max_fd, rfd);
	channel_max_fd = MAX(channel_max_fd, wfd);
	channel_max_fd = MAX(channel_max_fd, efd);

	if (rfd != -1)
		fcntl(rfd, F_SETFD, FD_CLOEXEC);
	if (wfd != -1 && wfd != rfd)
		fcntl(wfd, F_SETFD, FD_CLOEXEC);
	if (efd != -1 && efd != rfd && efd != wfd)
		fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	if ((c->isatty = is_tty) != 0)
		debug2("channel %u: rfd %d isatty", c->self, c->rfd);

	/* enable nonblocking mode */
	if (nonblock) {
		if (rfd != -1)
			set_nonblock(rfd);
		if (wfd != -1)
			set_nonblock(wfd);
		if (efd != -1)
			set_nonblock(efd);
	}
}

/*
 * Allocate a new channel object and set its type and socket. This will cause
 * remote_name to be freed.
 */
Channel *
channel_new(struct ssh *ssh, char *ctype, int type, int rfd, int wfd, int efd,
    u_int window, u_int maxpack, int extusage, char *remote_name, int nonblock)
{
	int found;
	u_int i;
	Channel *c;

	/* Do initial allocation if this is the first call. */
	if (channels_alloc == 0) {
		channels_alloc = 10;
		channels = xcalloc(channels_alloc, sizeof(Channel *));
		for (i = 0; i < channels_alloc; i++)
			channels[i] = NULL;
	}
	/* Try to find a free slot where to put the new channel. */
	for (found = -1, i = 0; i < channels_alloc; i++)
		if (channels[i] == NULL) {
			/* Found a free slot. */
			found = (int)i;
			break;
		}
	if (found < 0) {
		/* There are no free slots.  Take last+1 slot and expand the array.  */
		found = channels_alloc;
		if (channels_alloc > 10000)
			fatal("channel_new: internal error: channels_alloc %d "
			    "too big.", channels_alloc);
		channels = xrealloc(channels, channels_alloc + 10,
		    sizeof(Channel *));
		channels_alloc += 10;
		debug2("channel: expanding %d", channels_alloc);
		for (i = found; i < channels_alloc; i++)
			channels[i] = NULL;
	}
	/* Initialize and return new channel. */
	c = channels[found] = xcalloc(1, sizeof(Channel));
	if ((c->input = sshbuf_new()) == NULL ||
	    (c->output = sshbuf_new()) == NULL ||
	    (c->extended = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	c->ssh = ssh;
	c->path = NULL;
	c->listening_addr = NULL;
	c->listening_port = 0;
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_INPUT_OPEN;
	c->flags = 0;
	channel_register_fds(c, rfd, wfd, efd, extusage, nonblock, 0);
	c->notbefore = 0;
	c->self = found;
	c->type = type;
	c->ctype = ctype;
	c->local_window = window;
	c->local_window_max = window;
	c->local_consumed = 0;
	c->local_maxpacket = maxpack;
	c->remote_id = CHANNEL_ID_NONE;
	c->remote_name = xstrdup(remote_name);
	c->remote_window = 0;
	c->remote_maxpacket = 0;
	c->force_drain = 0;
	c->single_connection = 0;
	c->detach_user = NULL;
	c->detach_close = 0;
	c->open_confirm = NULL;
	c->open_confirm_ctx = NULL;
	c->input_filter = NULL;
	c->output_filter = NULL;
	c->filter_ctx = NULL;
	c->filter_cleanup = NULL;
	c->ctl_chan = CHANNEL_ID_NONE;
	c->mux_rcb = NULL;
	c->mux_ctx = NULL;
	c->mux_pause = 0;
	c->delayed = 1;		/* prevent call to channel_post handler */
	TAILQ_INIT(&c->status_confirms);
	debug("channel %u: new [%s]", found, remote_name);
	return c;
}

static int
channel_find_maxfd(void)
{
	u_int i;
	int max = 0;
	Channel *c;

	for (i = 0; i < channels_alloc; i++) {
		c = channels[i];
		if (c != NULL) {
			max = MAX(max, c->rfd);
			max = MAX(max, c->wfd);
			max = MAX(max, c->efd);
		}
	}
	return max;
}

int
channel_close_fd(int *fdp)
{
	int ret = 0, fd = *fdp;

	if (fd != -1) {
		ret = close(fd);
		*fdp = -1;
		if (fd == channel_max_fd)
			channel_max_fd = channel_find_maxfd();
	}
	return ret;
}

/* Close all channel fd/socket. */
static void
channel_close_fds(Channel *c)
{
	channel_close_fd(&c->sock);
	channel_close_fd(&c->rfd);
	channel_close_fd(&c->wfd);
	channel_close_fd(&c->efd);
}

/* Free the channel and close its fd/socket. */
void
channel_free(Channel *c)
{
	char *s;
	u_int i, n;
	struct channel_confirm *cc;

	for (n = 0, i = 0; i < channels_alloc; i++)
		if (channels[i])
			n++;
	debug("channel %u: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	s = channel_open_message();
	debug3("channel %u: status: %s", c->self, s);
	free(s);

	if (c->sock != -1)
		shutdown(c->sock, SHUT_RDWR);
	channel_close_fds(c);
	sshbuf_free(c->input);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	if (c->remote_name) {
		free(c->remote_name);
		c->remote_name = NULL;
	}
	if (c->path) {
		free(c->path);
		c->path = NULL;
	}
	if (c->listening_addr) {
		free(c->listening_addr);
		c->listening_addr = NULL;
	}
	while ((cc = TAILQ_FIRST(&c->status_confirms)) != NULL) {
		if (cc->abandon_cb != NULL)
			cc->abandon_cb(c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		bzero(cc, sizeof(*cc));
		free(cc);
	}
	if (c->filter_cleanup != NULL && c->filter_ctx != NULL)
		c->filter_cleanup(c->self, c->filter_ctx);
	channels[c->self] = NULL;
	free(c);
}

void
channel_free_all(void)
{
	u_int i;

	for (i = 0; i < channels_alloc; i++)
		if (channels[i] != NULL)
			channel_free(channels[i]);
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
void
channel_close_all(void)
{
	u_int i;

	for (i = 0; i < channels_alloc; i++)
		if (channels[i] != NULL)
			channel_close_fds(channels[i]);
}

/*
 * Stop listening to channels.
 */
void
channel_stop_listening(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < channels_alloc; i++) {
		c = channels[i];
		if (c != NULL) {
			switch (c->type) {
			case SSH_CHANNEL_AUTH_SOCKET:
			case SSH_CHANNEL_PORT_LISTENER:
			case SSH_CHANNEL_RPORT_LISTENER:
			case SSH_CHANNEL_X11_LISTENER:
				channel_close_fd(&c->sock);
				channel_free(c);
				break;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
int
channel_not_very_much_buffered_data(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < channels_alloc; i++) {
		c = channels[i];
		if (c != NULL && c->type == SSH_CHANNEL_OPEN) {
#if 0
			if (!compat20 &&
			    sshbuf_len(c->input) >
			    ssh_packet_get_maxsize(c->ssh)) {
				debug2("channel %u: big input buffer %d",
				    c->self, sshbuf_len(c->input));
				return 0;
			}
#endif
			if (sshbuf_len(c->output) >
			    ssh_packet_get_maxsize(c->ssh)) {
				debug2("channel %u: big output buffer %zu > %u",
				    c->self, sshbuf_len(c->output),
				    ssh_packet_get_maxsize(c->ssh));
				return 0;
			}
		}
	}
	return 1;
}

/* Returns true if any channel is still open. */
int
channel_still_open(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < channels_alloc; i++) {
		c = channels[i];
		if (c == NULL)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_MUX_LISTENER:
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_ZOMBIE:
		case SSH_CHANNEL_ABANDONED:
			continue;
		case SSH_CHANNEL_LARVAL:
			if (!compat20)
				fatal("cannot happen: SSH_CHANNEL_LARVAL");
			continue;
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
		case SSH_CHANNEL_MUX_CLIENT:
			return 1;
		case SSH_CHANNEL_INPUT_DRAINING:
		case SSH_CHANNEL_OUTPUT_DRAINING:
			if (!compat13)
				fatal("cannot happen: OUT_DRAIN");
			return 1;
		default:
			fatal("channel_still_open: bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	return 0;
}

/* Returns the id of an open channel suitable for keepaliving */
u_int
channel_find_open(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < channels_alloc; i++) {
		c = channels[i];
		if (c == NULL)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_MUX_LISTENER:
		case SSH_CHANNEL_MUX_CLIENT:
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_ZOMBIE:
		case SSH_CHANNEL_ABANDONED:
			continue;
		case SSH_CHANNEL_LARVAL:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
			return i;
		case SSH_CHANNEL_INPUT_DRAINING:
		case SSH_CHANNEL_OUTPUT_DRAINING:
			if (!compat13)
				fatal("cannot happen: OUT_DRAIN");
			return i;
		default:
			fatal("channel_find_open: bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	return CHANNEL_ID_NONE;
}


/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
char *
channel_open_message(void)
{
	struct sshbuf *msg;
	Channel *c;
	char *cp;
	u_int i;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_putf(msg, "The following connections are "
	    "open:\r\n")) != 0)
		fatal("%s: sshbuf_putf failed: %s", __func__, ssh_err(r));
	for (i = 0; i < channels_alloc; i++) {
		c = channels[i];
		if (c == NULL)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_ZOMBIE:
		case SSH_CHANNEL_ABANDONED:
		case SSH_CHANNEL_MUX_CLIENT:
		case SSH_CHANNEL_MUX_LISTENER:
			continue;
		case SSH_CHANNEL_LARVAL:
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
		case SSH_CHANNEL_INPUT_DRAINING:
		case SSH_CHANNEL_OUTPUT_DRAINING:
			if ((r = sshbuf_putf(msg,
			    "  #%u %.300s (t%d r%d i%d/%zu o%d/%zu fd %d/%d cc %d)\r\n",
			    c->self, c->remote_name,
			    c->type, c->remote_id,
			    c->istate, sshbuf_len(c->input),
			    c->ostate, sshbuf_len(c->output),
			    c->rfd, c->wfd, c->ctl_chan)) != 0)
				fatal("%s: sshbuf_putf failed: %s",
				    __func__, ssh_err(r));
			continue;
		default:
			fatal("channel_open_message: bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	if ((r = sshbuf_put_u8(msg, 0)) != 0)
		fatal("%s: sshbuf_put_u8 failed: %s", __func__, ssh_err(r));
	cp = xstrdup((const char *)sshbuf_ptr(msg));
	sshbuf_free(msg);
	return cp;
}

void
channel_send_open(u_int id)
{
	Channel *c = channel_lookup(id);
	struct ssh *ssh;
	int r;

	if (c == NULL) {
		logit("channel_send_open: %d: bad id", id);
		return;
	}
	ssh = c->ssh;
	debug2("channel %u: send open", id);
	if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, c->ctype)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		CHANNEL_PACKET_ERROR(c, r);
}

void
channel_request_start(u_int id, char *service, int wantconfirm)
{
	Channel *c = channel_lookup(id);
	struct ssh *ssh;
	int r;

	if (c == NULL) {
		logit("channel_request_start: %u: unknown channel id", id);
		return;
	}
	ssh = c->ssh;
	debug2("channel %u: request %s confirm %d", id, service, wantconfirm);
	if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0)
		CHANNEL_PACKET_ERROR(c, r);
}

void
channel_register_status_confirm(u_int id, channel_confirm_cb *cb,
    channel_confirm_abandon_cb *abandon_cb, void *ctx)
{
	struct channel_confirm *cc;
	Channel *c;

	if ((c = channel_lookup(id)) == NULL)
		fatal("channel_register_expect: %u: bad id", id);

	cc = xmalloc(sizeof(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

void
channel_register_open_confirm(u_int id, channel_open_fn *fn, void *ctx)
{
	Channel *c = channel_lookup(id);

	if (c == NULL) {
		logit("channel_register_open_confirm: %u: bad id", id);
		return;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

void
channel_register_cleanup(u_int id, channel_callback_fn *fn, int do_close)
{
	Channel *c = channel_by_id(id);

	if (c == NULL) {
		logit("channel_register_cleanup: %u: bad id", id);
		return;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

void
channel_cancel_cleanup(u_int id)
{
	Channel *c = channel_by_id(id);

	if (c == NULL) {
		logit("channel_cancel_cleanup: %u: bad id", id);
		return;
	}
	c->detach_user = NULL;
	c->detach_close = 0;
}

void
channel_register_filter(u_int id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, void *ctx)
{
	Channel *c = channel_lookup(id);

	if (c == NULL) {
		logit("channel_register_filter: %u: bad id", id);
		return;
	}
	c->input_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

void
channel_set_fds(u_int id, int rfd, int wfd, int efd,
    int extusage, int nonblock, int is_tty, u_int window_max)
{
	Channel *c = channel_lookup(id);
	struct ssh *ssh;
	int r;

	if (c == NULL || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %u.", id);
	ssh = c->ssh;
	channel_register_fds(c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	c->local_window = c->local_window_max = window_max;

	if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		CHANNEL_PACKET_ERROR(c, r);
}

/*
 * 'channel_pre*' are called just before select() to add any bits relevant to
 * channels in the select bitmasks.
 */
/*
 * 'channel_post*': perform any appropriate operations for channels which
 * have events pending.
 */
typedef void chan_fn(Channel *c, fd_set *readset, fd_set *writeset);
chan_fn *channel_pre[SSH_CHANNEL_MAX_TYPE];
chan_fn *channel_post[SSH_CHANNEL_MAX_TYPE];

/* ARGSUSED */
static void
channel_pre_listener(Channel *c, fd_set *readset, fd_set *writeset)
{
	FD_SET(c->sock, readset);
}

/* ARGSUSED */
static void
channel_pre_connecting(Channel *c, fd_set *readset, fd_set *writeset)
{
	debug3("channel %u: waiting for connection", c->self);
	FD_SET(c->sock, writeset);
}

static void
channel_pre_open_13(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;

	if (sshbuf_len(c->input) < ssh_packet_get_maxsize(ssh))
		FD_SET(c->sock, readset);
	if (sshbuf_len(c->output) > 0)
		FD_SET(c->sock, writeset);
}

static void
channel_pre_open(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;
	u_int limit = compat20 ? c->remote_window : ssh_packet_get_maxsize(ssh);

	if (c->istate == CHAN_INPUT_OPEN &&
	    limit > 0 &&
	    sshbuf_len(c->input) < limit &&
	    sshbuf_check_reserve(c->input, CHAN_RBUF) == 0)
		FD_SET(c->rfd, readset);
	if (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		if (sshbuf_len(c->output) > 0) {
			FD_SET(c->wfd, writeset);
		} else if (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			if (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %u: "
				    "obuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			else
				chan_obuf_empty(c);
		}
	}
	/** XXX check close conditions, too */
	if (compat20 && c->efd != -1 && 
	    !(c->istate == CHAN_INPUT_CLOSED && c->ostate == CHAN_OUTPUT_CLOSED)) {
		if (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			FD_SET(c->efd, writeset);
		else if (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    sshbuf_len(c->extended) < c->remote_window)
			FD_SET(c->efd, readset);
	}
	/* XXX: What about efd? races? */
}

/* ARGSUSED */
static void
channel_pre_input_draining(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;
	int r;

	if (sshbuf_len(c->input) == 0) {
		if ((r = sshpkt_start(ssh, SSH_MSG_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
		c->type = SSH_CHANNEL_CLOSED;
		debug2("channel %u: closing after input drain.", c->self);
	}
}

/* ARGSUSED */
static void
channel_pre_output_draining(Channel *c, fd_set *readset, fd_set *writeset)
{
	if (sshbuf_len(c->output) == 0)
		chan_mark_dead(c);
	else
		FD_SET(c->sock, writeset);
}

/*
 * This is a special state for X11 authentication spoofing.  An opened X11
 * connection (when authentication spoofing is being done) remains in this
 * state until the first packet has been completely read.  The authentication
 * data in that packet is then substituted by the real data if it matches the
 * fake data, and the channel is put into normal mode.
 * XXX All this happens at the client side.
 * Returns: 0 = need more data, -1 = wrong cookie, 1 = ok
 */
static int
x11_open_helper(struct sshbuf *b)
{
	u_char *ucp;
	u_int proto_len, data_len;

	/* Check if the fixed size part of the packet is in buffer. */
	if (sshbuf_len(b) < 12)
		return 0;

	/* Parse the lengths of variable-length fields. */
	if ((ucp = sshbuf_mutable_ptr(b)) == NULL)
		return -1;
	if (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} else if (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} else {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		return -1;
	}

	/* Check if the whole packet is in buffer. */
	if (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		return 0;

	/* Check if authentication protocol matches. */
	if (proto_len != strlen(x11_saved_proto) ||
	    memcmp(ucp + 12, x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		return -1;
	}
	/* Check if authentication data matches our fake data. */
	if (data_len != x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		x11_fake_data, x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		return -1;
	}
	/* Check fake data length */
	if (x11_fake_data_len != x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    x11_fake_data_len, x11_saved_data_len);
		return -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    x11_saved_data, x11_saved_data_len);
	return 1;
}

static void
channel_pre_x11_open_13(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;
	int r, ret = x11_open_helper(c->output);

	if (ret == 1) {
		/* Start normal processing for the channel. */
		c->type = SSH_CHANNEL_OPEN;
		channel_pre_open_13(c, readset, writeset);
	} else if (ret == -1) {
		/*
		 * We have received an X11 connection that has bad
		 * authentication information.
		 */
		logit("X11 connection rejected because of wrong authentication.");
		sshbuf_reset(c->input);
		sshbuf_reset(c->output);
		channel_close_fd(&c->sock);
		c->sock = -1;
		c->type = SSH_CHANNEL_CLOSED;
		if ((r = sshpkt_start(ssh, SSH_MSG_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
	}
}

static void
channel_pre_x11_open(Channel *c, fd_set *readset, fd_set *writeset)
{
	int ret = x11_open_helper(c->output);

	/* c->force_drain = 1; */

	if (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_pre_open(c, readset, writeset);
	} else if (ret == -1) {
		logit("X11 connection rejected because of wrong authentication.");
		debug2("X11 rejected %u i%d/o%d", c->self, c->istate, c->ostate);
		chan_read_failed(c);
		sshbuf_reset(c->input);
		chan_ibuf_empty(c);
		sshbuf_reset(c->output);
		/* for proto v1, the peer will send an IEOF */
		if (compat20)
			chan_write_failed(c);
		else
			c->type = SSH_CHANNEL_OPEN;
		debug2("X11 closed %u i%d/o%d", c->self, c->istate, c->ostate);
	}
}

static void
channel_pre_mux_client(Channel *c, fd_set *readset, fd_set *writeset)
{
	if (c->istate == CHAN_INPUT_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->input, CHAN_RBUF) == 0)
		FD_SET(c->rfd, readset);
	if (c->istate == CHAN_INPUT_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->input);
		chan_ibuf_empty(c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(c);
	}
	if (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		if (sshbuf_len(c->output) > 0)
			FD_SET(c->wfd, writeset);
		else if (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(c);
	}
}

void
channel_error(Channel *c, char *msg, int r, const char *func)
{
	if (c)
		fatal("%s: %s error: %s", func, msg, ssh_err(r));
	else
		fatal("%s: channel %u: %s error: %s", func, c->self,
		    msg, ssh_err(r));
}

/* try to decode a socks4 header */
/* ARGSUSED */
static int
channel_decode_socks4(Channel *c, fd_set *readset, fd_set *writeset)
{
	const char *p, *host;
	u_int len, have, i, found, need;
	char username[256];
	struct {
		u_int8_t version;
		u_int8_t command;
		u_int16_t dest_port;
		struct in_addr dest_addr;
	} s4_req, s4_rsp;
	int r;

	debug2("channel %u: decode socks4", c->self);

	have = sshbuf_len(c->input);
	len = sizeof(s4_req);
	if (have < len)
		return 0;
	p = (const char *)sshbuf_ptr(c->input);

	need = 1;
	/* SOCKS4A uses an invalid IP address 0.0.0.x */
	if (p[4] == 0 && p[5] == 0 && p[6] == 0 && p[7] != 0) {
		debug2("channel %u: socks4a request", c->self);
		/* ... and needs an extra string (the hostname) */
		need = 2;
	}
	/* Check for terminating NUL on the string(s) */
	for (found = 0, i = len; i < have; i++) {
		if (p[i] == '\0') {
			found++;
			if (found == need)
				break;
		}
		if (i > 1024) {
			/* the peer is probably sending garbage */
			debug("channel %u: decode socks4: too long",
			    c->self);
			return -1;
		}
	}
	if (found < need)
		return 0;
	if ((r = sshbuf_get_u8(c->input, &s4_req.version)) != 0 ||
	    (r = sshbuf_get_u8(c->input, &s4_req.command)) != 0 ||
	    (r = sshbuf_get_u16(c->input, &s4_req.dest_port)) != 0 ||
	    (r = sshbuf_get(c->input,
	    &s4_req.dest_addr, sizeof(s4_req.dest_addr)) != 0))
		CHANNEL_BUFFER_ERROR(c, r);
	have = sshbuf_len(c->input);
	p = (const char *)sshbuf_ptr(c->input);
	len = strlen(p);
	debug2("channel %u: decode socks4: user %s/%d", c->self, p, len);
	len++;					/* trailing '\0' */
	if (len > have)
		fatal("channel %u: decode socks4: len %d > have %d",
		    c->self, len, have);
	strlcpy(username, p, sizeof(username));
	sshbuf_consume(c->input, len);

	free(c->path);
	c->path = NULL;
	if (need == 1) {			/* SOCKS4: one string */
		host = inet_ntoa(s4_req.dest_addr);
		c->path = xstrdup(host);
	} else {				/* SOCKS4A: two strings */
		have = sshbuf_len(c->input);
		p = (const char *)sshbuf_ptr(c->input);
		len = strlen(p);
		debug2("channel %u: decode socks4a: host %s/%d",
		    c->self, p, len);
		len++;				/* trailing '\0' */
		if (len > have)
			fatal("channel %u: decode socks4a: len %d > have %d",
			    c->self, len, have);
		if (len > NI_MAXHOST) {
			error("channel %u: hostname \"%.100s\" too long",
			    c->self, p);
			return -1;
		}
		c->path = xstrdup(p);
		if ((r = sshbuf_consume(c->input, len)) != 0)
			CHANNEL_BUFFER_ERROR(c, r);
	}
	c->host_port = s4_req.dest_port;

	debug2("channel %u: dynamic request: socks4 host %s port %u command %u",
	    c->self, c->path, c->host_port, s4_req.command);

	if (s4_req.command != 1) {
		debug("channel %u: cannot handle: %s cn %d",
		    c->self, need == 1 ? "SOCKS4" : "SOCKS4A", s4_req.command);
		return -1;
	}
	s4_rsp.version = 0;			/* vn: 0 for reply */
	s4_rsp.command = 90;			/* cd: req granted */
	s4_rsp.dest_port = 0;			/* ignored */
	s4_rsp.dest_addr.s_addr = INADDR_ANY;	/* ignored */
	if ((r = sshbuf_put(c->output, &s4_rsp, sizeof(s4_rsp))) != 0)
		CHANNEL_BUFFER_ERROR(c, r);
	return 1;
}

/* try to decode a socks5 header */
#define SSH_SOCKS5_AUTHDONE	0x1000
#define SSH_SOCKS5_NOAUTH	0x00
#define SSH_SOCKS5_IPV4		0x01
#define SSH_SOCKS5_DOMAIN	0x03
#define SSH_SOCKS5_IPV6		0x04
#define SSH_SOCKS5_CONNECT	0x01
#define SSH_SOCKS5_SUCCESS	0x00

/* ARGSUSED */
static int
channel_decode_socks5(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct {
		u_int8_t version;
		u_int8_t command;
		u_int8_t reserved;
		u_int8_t atyp;
	} s5_req, s5_rsp;
	u_int16_t dest_port;
	const u_char *p;
	char dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int have, need, i, found, nmethods, addrlen, af;
	int r;

	debug2("channel %u: decode socks5", c->self);
	p = sshbuf_ptr(c->input);
	if (p[0] != 0x05)
		return -1;
	have = sshbuf_len(c->input);
	if (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		/* format: ver | nmethods | methods */
		if (have < 2)
			return 0;
		nmethods = p[1];
		if (have < nmethods + 2)
			return 0;
		/* look for method: "NO AUTHENTICATION REQUIRED" */
		for (found = 0, i = 2; i < nmethods + 2; i++) {
			if (p[i] == SSH_SOCKS5_NOAUTH) {
				found = 1;
				break;
			}
		}
		if (!found) {
			debug("channel %u: method SSH_SOCKS5_NOAUTH not found",
			    c->self);
			return -1;
		}
		if ((r = sshbuf_consume(c->input, nmethods + 2)) != 0 ||
		    (r = sshbuf_put_u8(c->output, 0x05)) != 0 || /* version */
		    (r = sshbuf_put_u8(c->output, SSH_SOCKS5_NOAUTH)) != 0)
			CHANNEL_BUFFER_ERROR(c, r);
		FD_SET(c->sock, writeset);
		c->flags |= SSH_SOCKS5_AUTHDONE;
		debug2("channel %u: socks5 auth done", c->self);
		return 0;				/* need more */
	}
	debug2("channel %u: socks5 post auth", c->self);
	if (have < sizeof(s5_req)+1)
		return 0;			/* need more */
	memcpy(&s5_req, p, sizeof(s5_req));
	if (s5_req.version != 0x05 ||
	    s5_req.command != SSH_SOCKS5_CONNECT ||
	    s5_req.reserved != 0x00) {
		debug2("channel %u: only socks5 connect supported", c->self);
		return -1;
	}
	switch (s5_req.atyp){
	case SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		break;
	case SSH_SOCKS5_DOMAIN:
		addrlen = p[sizeof(s5_req)];
		af = -1;
		break;
	case SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		break;
	default:
		debug2("channel %u: bad socks5 atyp %d", c->self, s5_req.atyp);
		return -1;
	}
	need = sizeof(s5_req) + addrlen + 2;
	if (s5_req.atyp == SSH_SOCKS5_DOMAIN)
		need++;
	if (have < need)
		return 0;
	/* Need to consume host string length for SSH_SOCKS5_DOMAIN requests */
	i = sizeof(s5_req) + (s5_req.atyp == SSH_SOCKS5_DOMAIN ? 1 : 0);
	if ((r = sshbuf_consume(c->input, i)) != 0 ||
	    (r = sshbuf_get(c->input, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get(c->input, &dest_port, 2)) != 0)
		CHANNEL_BUFFER_ERROR(c, r);
	dest_addr[addrlen] = '\0';
	free(c->path);
	c->path = NULL;
	if (s5_req.atyp == SSH_SOCKS5_DOMAIN) {
		if (addrlen >= NI_MAXHOST) {
			error("channel %u: dynamic request: socks5 hostname "
			    "\"%.100s\" too long", c->self, dest_addr);
			return -1;
		}
		c->path = xstrdup(dest_addr);
	} else {
		if (inet_ntop(af, dest_addr, ntop, sizeof(ntop)) == NULL)
			return -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = ntohs(dest_port);

	debug2("channel %u: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, s5_req.command);

	s5_rsp.version = 0x05;
	s5_rsp.command = SSH_SOCKS5_SUCCESS;
	s5_rsp.reserved = 0;			/* ignored */
	s5_rsp.atyp = SSH_SOCKS5_IPV4;
	((struct in_addr *)&dest_addr)->s_addr = INADDR_ANY;
	dest_port = 0;				/* ignored */

	if ((r = sshbuf_put(c->output, &s5_rsp, sizeof(s5_rsp))) != 0 ||
	    (r = sshbuf_put(c->output, &dest_addr,
	    sizeof(struct in_addr))) != 0 ||
	    (r = sshbuf_put(c->output, &dest_port, sizeof(dest_port))) != 0)
		CHANNEL_BUFFER_ERROR(c, r);
	return 1;
}

Channel *
channel_connect_stdio_fwd(struct ssh *ssh, const char *host_to_connect,
    u_short port_to_connect, int in, int out)
{
	Channel *c;

	debug("channel_connect_stdio_fwd %s:%d", host_to_connect,
	    port_to_connect);

	c = channel_new(ssh, "stdio-forward", SSH_CHANNEL_OPENING, in, out,
	    -1, CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "stdio-forward", /*nonblock*/0);

	c->path = xstrdup(host_to_connect);
	c->host_port = port_to_connect;
	c->listening_port = 0;
	c->force_drain = 1;

	channel_register_fds(c, in, out, -1, 0, 1, 0);
	port_open_helper(c, "direct-tcpip");

	return c;
}

/* dynamic port forwarding */
static void
channel_pre_dynamic(Channel *c, fd_set *readset, fd_set *writeset)
{
	const u_char *p;
	u_int have;
	int ret;

	have = sshbuf_len(c->input);
	debug2("channel %u: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	if (have < 3) {
		/* need more */
		FD_SET(c->sock, readset);
		return;
	}
	/* try to guess the protocol */
	p = sshbuf_ptr(c->input);
	switch (p[0]) {
	case 0x04:
		ret = channel_decode_socks4(c, readset, writeset);
		break;
	case 0x05:
		ret = channel_decode_socks5(c, readset, writeset);
		break;
	default:
		ret = -1;
		break;
	}
	if (ret < 0) {
		chan_mark_dead(c);
	} else if (ret == 0) {
		debug2("channel %u: pre_dynamic: need more", c->self);
		/* need more */
		FD_SET(c->sock, readset);
	} else {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(c, "direct-tcpip");
	}
}

/* This is our fake X11 server socket. */
/* ARGSUSED */
static void
channel_post_x11_listener(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;
	Channel *nc;
	struct sockaddr_storage addr;
	int r, newsock, oerrno;
	socklen_t addrlen;
	char buf[16384], *remote_ipaddr;
	int remote_port;

	if (FD_ISSET(c->sock, readset)) {
		debug("X11 connection requested.");
		addrlen = sizeof(addr);
		newsock = accept(c->sock, (struct sockaddr *)&addr, &addrlen);
		if (c->single_connection) {
			oerrno = errno;
			debug2("single_connection: closing X11 listener.");
			channel_close_fd(&c->sock);
			chan_mark_dead(c);
			errno = oerrno;
		}
		if (newsock < 0) {
			if (errno != EINTR && errno != EWOULDBLOCK &&
			    errno != ECONNABORTED)
				error("accept: %.100s", strerror(errno));
			if (errno == EMFILE || errno == ENFILE)
				c->notbefore = monotime() + 1;
			return;
		}
		set_nodelay(newsock);
		remote_ipaddr = get_peer_ipaddr(newsock);
		remote_port = get_peer_port(newsock);
		snprintf(buf, sizeof buf, "X11 connection from %.200s port %d",
		    remote_ipaddr, remote_port);

		nc = channel_new(c->ssh, "accepted x11 socket",
		    SSH_CHANNEL_OPENING, newsock, newsock, -1,
		    c->local_window_max, c->local_maxpacket, 0, buf, 1);
		if (compat20) {
			if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "x11")) != 0 ||
			    (r = sshpkt_put_u32(ssh, nc->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, nc->local_window_max)) != 0 ||
			    (r = sshpkt_put_u32(ssh, nc->local_maxpacket)) != 0 ||
			    /* originator ipaddr and port */
			    (r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
			    (!(ssh->compat & SSH_BUG_X11FWD) &&
			    (r = sshpkt_put_u32(ssh, remote_port)) != 0) ||
			    (r = sshpkt_send(ssh)) != 0)
				CHANNEL_PACKET_ERROR(c, r);
		} else {
			u_int flags = ssh_packet_get_protocol_flags(ssh);

			if ((r = sshpkt_start(ssh, SSH_SMSG_X11_OPEN)) != 0 ||
			    (r = sshpkt_put_u32(ssh, nc->self)) != 0 ||
			    ((flags & SSH_PROTOFLAG_HOST_IN_FWD_OPEN) &&
			    (r = sshpkt_put_cstring(ssh, buf)) != 0) ||
			    (r = sshpkt_send(ssh)) != 0)
				CHANNEL_PACKET_ERROR(c, r);
		}
		free(remote_ipaddr);
	}
}

static void
port_open_helper(Channel *c, char *rtype)
{
	struct ssh *ssh = c->ssh;
	int r, direct;
	char buf[1024];
	char *remote_ipaddr = get_peer_ipaddr(c->sock);
	int remote_port = get_peer_port(c->sock);

	if (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		free(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	direct = (strcmp(rtype, "direct-tcpip") == 0);

	snprintf(buf, sizeof buf,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port);

	free(c->remote_name);
	c->remote_name = xstrdup(buf);

	if (compat20) {
		if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, rtype)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh,
		    direct ? c->host_port : c->listening_port)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
	} else {
		u_int flags = ssh_packet_get_protocol_flags(ssh);

		if ((r = sshpkt_start(ssh, SSH_MSG_PORT_OPEN)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0 ||
		    ((flags & SSH_PROTOFLAG_HOST_IN_FWD_OPEN) &&
		    (r = sshpkt_put_cstring(ssh, c->remote_name)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
	}
	free(remote_ipaddr);
}

static void
channel_set_reuseaddr(int fd)
{
	int on = 1;

	/*
	 * Set socket options.
	 * Allow local port reuse in TIME_WAIT.
	 */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
/* ARGSUSED */
static void
channel_post_port_listener(Channel *c, fd_set *readset, fd_set *writeset)
{
	Channel *nc;
	struct sockaddr_storage addr;
	int newsock, nextstate;
	socklen_t addrlen;
	char *rtype;

	if (FD_ISSET(c->sock, readset)) {
		debug("Connection to port %d forwarding "
		    "to %.100s port %d requested.",
		    c->listening_port, c->path, c->host_port);

		if (c->type == SSH_CHANNEL_RPORT_LISTENER) {
			nextstate = SSH_CHANNEL_OPENING;
			rtype = "forwarded-tcpip";
		} else {
			if (c->host_port == 0) {
				nextstate = SSH_CHANNEL_DYNAMIC;
				rtype = "dynamic-tcpip";
			} else {
				nextstate = SSH_CHANNEL_OPENING;
				rtype = "direct-tcpip";
			}
		}

		addrlen = sizeof(addr);
		newsock = accept(c->sock, (struct sockaddr *)&addr, &addrlen);
		if (newsock < 0) {
			if (errno != EINTR && errno != EWOULDBLOCK &&
			    errno != ECONNABORTED)
				error("accept: %.100s", strerror(errno));
			if (errno == EMFILE || errno == ENFILE)
				c->notbefore = monotime() + 1;
			return;
		}
		set_nodelay(newsock);
		nc = channel_new(c->ssh, rtype, nextstate, newsock, newsock,
		    -1, c->local_window_max, c->local_maxpacket, 0, rtype, 1);
		nc->listening_port = c->listening_port;
		nc->host_port = c->host_port;
		if (c->path != NULL)
			nc->path = xstrdup(c->path);

		if (nextstate != SSH_CHANNEL_DYNAMIC)
			port_open_helper(nc, rtype);
	}
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
/* ARGSUSED */
static void
channel_post_auth_listener(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;
	Channel *nc;
	int r, newsock;
	struct sockaddr_storage addr;
	socklen_t addrlen;

	if (FD_ISSET(c->sock, readset)) {
		addrlen = sizeof(addr);
		newsock = accept(c->sock, (struct sockaddr *)&addr, &addrlen);
		if (newsock < 0) {
			error("accept from auth socket: %.100s",
			    strerror(errno));
			if (errno == EMFILE || errno == ENFILE)
				c->notbefore = monotime() + 1;
			return;
		}
		nc = channel_new(c->ssh, "accepted auth socket",
		    SSH_CHANNEL_OPENING, newsock, newsock, -1,
		    c->local_window_max, c->local_maxpacket,
		    0, "accepted auth socket", 1);
		if (compat20) {
			if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
			    (r = sshpkt_put_cstring(ssh,
			    "auth-agent@openssh.com")) != 0 ||
			    (r = sshpkt_put_u32(ssh, nc->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				CHANNEL_PACKET_ERROR(c, r);
		} else {
			if ((r = sshpkt_start(ssh, SSH_SMSG_AGENT_OPEN)) != 0 ||
			    (r = sshpkt_put_u32(ssh, nc->self)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				CHANNEL_PACKET_ERROR(c, r);
		}
	}
}

/* ARGSUSED */
static void
channel_post_connecting(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;
	int r, err = 0, sock;
	socklen_t sz = sizeof(err);

	if (FD_ISSET(c->sock, writeset)) {
		if (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) < 0) {
			err = errno;
			error("getsockopt SO_ERROR failed");
		}
		if (err == 0) {
			debug("channel %u: connected to %s port %d",
			    c->self, c->connect_ctx.host, c->connect_ctx.port);
			channel_connect_ctx_free(&c->connect_ctx);
			c->type = SSH_CHANNEL_OPEN;
			if (compat20) {
				if ((r = sshpkt_start(ssh,
				    SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					CHANNEL_PACKET_ERROR(c, r);
			} else {
				if ((r = sshpkt_start(ssh,
				    SSH_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					CHANNEL_PACKET_ERROR(c, r);
			}
		} else {
			debug("channel %u: connection failed: %s",
			    c->self, strerror(err));
			/* Try next address, if any */
			if ((sock = connect_next(&c->connect_ctx)) > 0) {
				close(c->sock);
				c->sock = c->rfd = c->wfd = sock;
				channel_max_fd = channel_find_maxfd();
				return;
			}
			/* Exhausted all addresses */
			error("connect_to %.100s port %d: failed.",
			    c->connect_ctx.host, c->connect_ctx.port);
			channel_connect_ctx_free(&c->connect_ctx);
			if (compat20) {
				if ((r = sshpkt_start(ssh,
				    SSH2_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
				    (r = sshpkt_put_u32(ssh, SSH2_OPEN_CONNECT_FAILED)) != 0 ||
				    (!(ssh->compat & SSH_BUG_OPENFAILURE) &&
				    ((r = sshpkt_put_cstring(ssh, strerror(err))) != 0 ||
				    (r = sshpkt_put_cstring(ssh, "")) != 0)) ||
				    (r = sshpkt_send(ssh)) != 0)
					CHANNEL_PACKET_ERROR(c, r);
			} else {
				if ((r = sshpkt_start(ssh,
				    SSH_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					CHANNEL_PACKET_ERROR(c, r);
			}
			chan_mark_dead(c);
		}
	}
}

/* ARGSUSED */
static int
channel_handle_rfd(Channel *c, fd_set *readset, fd_set *writeset)
{
	char buf[CHAN_RBUF];
	int len, r;

	if (c->rfd != -1 &&
	    FD_ISSET(c->rfd, readset)) {
		len = read(c->rfd, buf, sizeof(buf));
		if (len < 0 && (errno == EINTR || errno == EAGAIN))
			return 1;
		if (len <= 0) {
			debug2("channel %u: read<=0 rfd %d len %d",
			    c->self, c->rfd, len);
			if (c->type != SSH_CHANNEL_OPEN) {
				debug2("channel %u: not open", c->self);
				chan_mark_dead(c);
				return -1;
			} else if (compat13) {
				sshbuf_reset(c->output);
				c->type = SSH_CHANNEL_INPUT_DRAINING;
				debug2("channel %u: input draining.", c->self);
			} else {
				chan_read_failed(c);
			}
			return -1;
		}
		if (c->input_filter != NULL) {
			if (c->input_filter(c, buf, len) == -1) {
				debug2("channel %u: filter stops", c->self);
				chan_read_failed(c);
			}
		} else if (c->datagram) {
			if ((r = sshbuf_put_string(c->input, buf, len)) != 0)
				CHANNEL_BUFFER_ERROR(c, r);
		} else {
			if ((r = sshbuf_put(c->input, buf, len)) != 0)
				CHANNEL_BUFFER_ERROR(c, r);
		}
	}
	return 1;
}

/* ARGSUSED */
static int
channel_handle_wfd(Channel *c, fd_set *readset, fd_set *writeset)
{
	struct ssh *ssh = c->ssh;
	struct termios tio;
	u_char *data = NULL, *buf;
	size_t dlen, olen = 0;
	int r, len;

	/* Send buffered output data to the socket. */
	if (c->wfd != -1 &&
	    FD_ISSET(c->wfd, writeset) &&
	    sshbuf_len(c->output) > 0) {
		olen = sshbuf_len(c->output);
		if (c->output_filter != NULL) {
			if ((buf = c->output_filter(c, &data, &dlen)) == NULL) {
				debug2("channel %u: filter stops", c->self);
				if (c->type != SSH_CHANNEL_OPEN)
					chan_mark_dead(c);
				else
					chan_write_failed(c);
				return -1;
			}
		} else if (c->datagram) {
			if ((r = sshbuf_get_string(c->output,
			    &buf, &dlen)) != 0)
				CHANNEL_BUFFER_ERROR(c, r);
			data = buf;
		} else {
			buf = data = (u_char *)sshbuf_ptr(c->output);
			dlen = sshbuf_len(c->output);
		}

		if (c->datagram) {
			/* ignore truncated writes, datagrams might get lost */
			len = write(c->wfd, buf, dlen);
			free(data);
			if (len < 0 && (errno == EINTR || errno == EAGAIN))
				return 1;
			if (len <= 0) {
				if (c->type != SSH_CHANNEL_OPEN)
					chan_mark_dead(c);
				else
					chan_write_failed(c);
				return -1;
			}
			goto out;
		}

		len = write(c->wfd, buf, dlen);
		if (len < 0 && (errno == EINTR || errno == EAGAIN))
			return 1;
		if (len <= 0) {
			if (c->type != SSH_CHANNEL_OPEN) {
				debug2("channel %u: not open", c->self);
				chan_mark_dead(c);
				return -1;
			} else if (compat13) {
				sshbuf_reset(c->output);
				debug2("channel %u: input draining.", c->self);
				c->type = SSH_CHANNEL_INPUT_DRAINING;
			} else {
				chan_write_failed(c);
			}
			return -1;
		}
		if (compat20 && c->isatty && dlen >= 1 && buf[0] != '\r') {
			if (tcgetattr(c->wfd, &tio) == 0 &&
			    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
				/*
				 * Simulate echo to reduce the impact of
				 * traffic analysis. We need to match the
				 * size of a SSH2_MSG_CHANNEL_DATA message
				 * (4 byte channel id + buf)
				 */
				ssh_packet_send_ignore(ssh, 4 + len);
				if ((r = sshpkt_send(ssh)) != 0)
					CHANNEL_PACKET_ERROR(c, r);
			}
		}
		if ((r = sshbuf_consume(c->output, len)) != 0)
			CHANNEL_BUFFER_ERROR(c, r);
	}
 out:
	if (compat20 && olen > 0)
		c->local_consumed += olen - sshbuf_len(c->output);
	return 1;
}

static int
channel_handle_efd(Channel *c, fd_set *readset, fd_set *writeset)
{
	char buf[CHAN_RBUF];
	int len, r;

/** XXX handle drain efd, too */
	if (c->efd != -1) {
		if (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    FD_ISSET(c->efd, writeset) &&
		    sshbuf_len(c->extended) > 0) {
			len = write(c->efd, sshbuf_ptr(c->extended),
			    sshbuf_len(c->extended));
			debug2("channel %u: written %d to efd %d",
			    c->self, len, c->efd);
			if (len < 0 && (errno == EINTR || errno == EAGAIN))
				return 1;
			if (len <= 0) {
				debug2("channel %u: closing write-efd %d",
				    c->self, c->efd);
				channel_close_fd(&c->efd);
			} else {
				if ((r = sshbuf_consume(c->extended, len)) != 0)
					CHANNEL_BUFFER_ERROR(c, r);
				c->local_consumed += len;
			}
		} else if (c->efd != -1 &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    FD_ISSET(c->efd, readset)) {
			len = read(c->efd, buf, sizeof(buf));
			debug2("channel %u: read %d from efd %d",
			    c->self, len, c->efd);
			if (len < 0 && (errno == EINTR || errno == EAGAIN))
				return 1;
			if (len <= 0) {
				debug2("channel %u: closing read-efd %d",
				    c->self, c->efd);
				channel_close_fd(&c->efd);
			} else {
				if (c->extended_usage == CHAN_EXTENDED_IGNORE) {
					debug3("channel %u: discard efd",
					    c->self);
				} else {
					if ((r = sshbuf_put(c->extended,
					    buf, len)) != 0)
						CHANNEL_BUFFER_ERROR(c, r);
				}
			}
		}
	}
	return 1;
}

/* ARGSUSED */
static int
channel_check_window(Channel *c)
{
	struct ssh *ssh = c->ssh;
	int r;

	if (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		if ((r = sshpkt_start(ssh,
		    SSH2_MSG_CHANNEL_WINDOW_ADJUST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_consumed)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
		debug2("channel %u: window %d sent adjust %d",
		    c->self, c->local_window,
		    c->local_consumed);
		c->local_window += c->local_consumed;
		c->local_consumed = 0;
	}
	return 1;
}

static void
channel_post_open(Channel *c, fd_set *readset, fd_set *writeset)
{
	channel_handle_rfd(c, readset, writeset);
	channel_handle_wfd(c, readset, writeset);
	if (!compat20)
		return;
	channel_handle_efd(c, readset, writeset);
	channel_check_window(c);
}

static u_int
read_mux(Channel *c, u_int need)
{
	char buf[CHAN_RBUF];
	int len, r;
	u_int rlen;

	if (sshbuf_len(c->input) < need) {
		rlen = need - sshbuf_len(c->input);
		len = read(c->rfd, buf, MIN(rlen, CHAN_RBUF));
		if (len <= 0) {
			if (errno != EINTR && errno != EAGAIN) {
				debug2("channel %u: ctl read<=0 rfd %d len %d",
				    c->self, c->rfd, len);
				chan_read_failed(c);
				return 0;
			}
		} else if ((r = sshbuf_put(c->input, buf, len)) != 0)
			CHANNEL_BUFFER_ERROR(c, r);
	}
	return sshbuf_len(c->input);
}

static void
channel_post_mux_client(Channel *c, fd_set *readset, fd_set *writeset)
{
	u_int need;
	ssize_t len;
	int r;

	if (!compat20)
		fatal("%s: entered with !compat20", __func__);

	if (c->rfd != -1 && !c->mux_pause && FD_ISSET(c->rfd, readset) &&
	    (c->istate == CHAN_INPUT_OPEN ||
	    c->istate == CHAN_INPUT_WAIT_DRAIN)) {
		/*
		 * Don't not read past the precise end of packets to
		 * avoid disrupting fd passing.
		 */
		if (read_mux(c, 4) < 4) /* read header */
			return;
		need = PEEK_U32(sshbuf_ptr(c->input));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
		if (need > CHANNEL_MUX_MAX_PACKET) {
			debug2("channel %u: packet too big %u > %u",
			    c->self, CHANNEL_MUX_MAX_PACKET, need);
			chan_rcvd_oclose(c);
			return;
		}
		if (read_mux(c, need + 4) < need + 4) /* read body */
			return;
		if (c->mux_rcb(c) != 0) {
			debug("channel %u: mux_rcb failed", c->self);
			chan_mark_dead(c);
			return;
		}
	}

	if (c->wfd != -1 && FD_ISSET(c->wfd, writeset) &&
	    sshbuf_len(c->output) > 0) {
		len = write(c->wfd, sshbuf_ptr(c->output),
		    sshbuf_len(c->output));
		if (len < 0 && (errno == EINTR || errno == EAGAIN))
			return;
		if (len <= 0) {
			chan_mark_dead(c);
			return;
		}
		if ((r = sshbuf_consume(c->output, len)) != 0)
			CHANNEL_BUFFER_ERROR(c, r);
	}
}

static void
channel_post_mux_listener(Channel *c, fd_set *readset, fd_set *writeset)
{
	Channel *nc;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int newsock;
	uid_t euid;
	gid_t egid;

	if (!FD_ISSET(c->sock, readset))
		return;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);
	if ((newsock = accept(c->sock, (struct sockaddr*)&addr,
	    &addrlen)) == -1) {
		error("%s accept: %s", __func__, strerror(errno));
		if (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime() + 1;
		return;
	}

	if (getpeereid(newsock, &euid, &egid) < 0) {
		error("%s getpeereid failed: %s", __func__,
		    strerror(errno));
		close(newsock);
		return;
	}
	if ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		return;
	}
	nc = channel_new(c->ssh, "multiplex client", SSH_CHANNEL_MUX_CLIENT,
	    newsock, newsock, -1, c->local_window_max,
	    c->local_maxpacket, 0, "mux-control", 1);
	nc->mux_rcb = c->mux_rcb;
	debug3("%s: new mux channel %d fd %d", __func__,
	    nc->self, nc->sock);
	/* establish state */
	nc->mux_rcb(nc);
	/* mux state transitions must not elicit protocol messages */
	nc->flags |= CHAN_LOCAL;
}

/* ARGSUSED */
static void
channel_post_output_drain_13(Channel *c, fd_set *readset, fd_set *writeset)
{
	int len, r;

	/* Send buffered output data to the socket. */
	if (FD_ISSET(c->sock, writeset) && sshbuf_len(c->output) > 0) {
		len = write(c->sock, sshbuf_ptr(c->output),
			    sshbuf_len(c->output));
		if (len <= 0)
			sshbuf_reset(c->output);
		else if ((r = sshbuf_consume(c->output, len)) != 0)
			CHANNEL_BUFFER_ERROR(c, r);
	}
}

static void
channel_handler_init_20(void)
{
	channel_pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	channel_pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	channel_pre[SSH_CHANNEL_PORT_LISTENER] =	&channel_pre_listener;
	channel_pre[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	channel_pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	channel_pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	channel_pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	channel_pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;
	channel_pre[SSH_CHANNEL_MUX_LISTENER] =		&channel_pre_listener;
	channel_pre[SSH_CHANNEL_MUX_CLIENT] =		&channel_pre_mux_client;

	channel_post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	channel_post[SSH_CHANNEL_PORT_LISTENER] =	&channel_post_port_listener;
	channel_post[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_port_listener;
	channel_post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	channel_post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	channel_post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	channel_post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
	channel_post[SSH_CHANNEL_MUX_LISTENER] =	&channel_post_mux_listener;
	channel_post[SSH_CHANNEL_MUX_CLIENT] =		&channel_post_mux_client;
}

static void
channel_handler_init_13(void)
{
	channel_pre[SSH_CHANNEL_OPEN] =			&channel_pre_open_13;
	channel_pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open_13;
	channel_pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	channel_pre[SSH_CHANNEL_PORT_LISTENER] =	&channel_pre_listener;
	channel_pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	channel_pre[SSH_CHANNEL_INPUT_DRAINING] =	&channel_pre_input_draining;
	channel_pre[SSH_CHANNEL_OUTPUT_DRAINING] =	&channel_pre_output_draining;
	channel_pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	channel_pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;

	channel_post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	channel_post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	channel_post[SSH_CHANNEL_PORT_LISTENER] =	&channel_post_port_listener;
	channel_post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	channel_post[SSH_CHANNEL_OUTPUT_DRAINING] =	&channel_post_output_drain_13;
	channel_post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	channel_post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
}

static void
channel_handler_init_15(void)
{
	channel_pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	channel_pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	channel_pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	channel_pre[SSH_CHANNEL_PORT_LISTENER] =	&channel_pre_listener;
	channel_pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	channel_pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	channel_pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;

	channel_post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	channel_post[SSH_CHANNEL_PORT_LISTENER] =	&channel_post_port_listener;
	channel_post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	channel_post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	channel_post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	channel_post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
}

static void
channel_handler_init(void)
{
	int i;

	for (i = 0; i < SSH_CHANNEL_MAX_TYPE; i++) {
		channel_pre[i] = NULL;
		channel_post[i] = NULL;
	}
	if (compat20)
		channel_handler_init_20();
	else if (compat13)
		channel_handler_init_13();
	else
		channel_handler_init_15();
}

/* gc dead channels */
static void
channel_garbage_collect(Channel *c)
{
	if (c == NULL)
		return;
	if (c->detach_user != NULL) {
		if (!chan_is_dead(c, c->detach_close))
			return;
		debug2("channel %u: gc: notify user", c->self);
		c->detach_user(c->self, NULL);
		/* if we still have a callback */
		if (c->detach_user != NULL)
			return;
		debug2("channel %u: gc: user detached", c->self);
	}
	if (!chan_is_dead(c, 1))
		return;
	debug2("channel %u: garbage collecting", c->self);
	channel_free(c);
}

static void
channel_handler(chan_fn *ftab[], fd_set *readset, fd_set *writeset,
    time_t *unpause_secs)
{
	static int did_init = 0;
	u_int i, oalloc;
	Channel *c;
	time_t now;

	if (!did_init) {
		channel_handler_init();
		did_init = 1;
	}
	now = monotime();
	if (unpause_secs != NULL)
		*unpause_secs = 0;
	for (i = 0, oalloc = channels_alloc; i < oalloc; i++) {
		c = channels[i];
		if (c == NULL)
			continue;
		if (c->delayed) {
			if (ftab == channel_pre)
				c->delayed = 0;
			else
				continue;
		}
		if (ftab[c->type] != NULL) {
			/*
			 * Run handlers that are not paused.
			 */
			if (c->notbefore <= now)
				(*ftab[c->type])(c, readset, writeset);
			else if (unpause_secs != NULL) {
				/*
				 * Collect the time that the earliest
				 * channel comes off pause.
				 */
				debug3("%s: chan %d: skip for %d more seconds",
				    __func__, c->self,
				    (int)(c->notbefore - now));
				if (*unpause_secs == 0 ||
				    (c->notbefore - now) < *unpause_secs)
					*unpause_secs = c->notbefore - now;
			}
		}
		channel_garbage_collect(c);
	}
	if (unpause_secs != NULL && *unpause_secs != 0)
		debug3("%s: first channel unpauses in %d seconds",
		    __func__, (int)*unpause_secs);
}

/*
 * Allocate/update select bitmasks and add any bits relevant to channels in
 * select bitmasks.
 */
void
channel_prepare_select(fd_set **readsetp, fd_set **writesetp, int *maxfdp,
    u_int *nallocp, time_t *minwait_secs, int rekeying)
{
	u_int n, sz, nfdset;

	n = MAX(*maxfdp, channel_max_fd);

	nfdset = howmany(n+1, NFDBITS);
	/* Explicitly test here, because xrealloc isn't always called */
	if (nfdset && SIZE_T_MAX / nfdset < sizeof(fd_mask))
		fatal("channel_prepare_select: max_fd (%d) is too large", n);
	sz = nfdset * sizeof(fd_mask);

	/* perhaps check sz < nalloc/2 and shrink? */
	if (*readsetp == NULL || sz > *nallocp) {
		*readsetp = xrealloc(*readsetp, nfdset, sizeof(fd_mask));
		*writesetp = xrealloc(*writesetp, nfdset, sizeof(fd_mask));
		*nallocp = sz;
	}
	*maxfdp = n;
	memset(*readsetp, 0, sz);
	memset(*writesetp, 0, sz);

	if (!rekeying)
		channel_handler(channel_pre, *readsetp, *writesetp,
		    minwait_secs);
}

/*
 * After select, perform any appropriate operations for channels which have
 * events pending.
 */
void
channel_after_select(fd_set *readset, fd_set *writeset)
{
	channel_handler(channel_post, readset, writeset, NULL);
}


/* If there is data to send to the connection, enqueue some of it now. */
void
channel_output_poll(void)
{
	struct ssh *ssh;
	Channel *c;
	u_int i, len;
	int r;

	for (i = 0; i < channels_alloc; i++) {
		c = channels[i];
		if (c == NULL)
			continue;

		ssh = c->ssh;
		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		if (compat13) {
			if (c->type != SSH_CHANNEL_OPEN &&
			    c->type != SSH_CHANNEL_INPUT_DRAINING)
				continue;
		} else {
			if (c->type != SSH_CHANNEL_OPEN)
				continue;
		}
		if (compat20 &&
		    (c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %u: will not send data after close", c->self);
			continue;
		}

		/* Get the amount of buffered data for this channel. */
		if ((c->istate == CHAN_INPUT_OPEN ||
		    c->istate == CHAN_INPUT_WAIT_DRAIN) &&
		    (len = sshbuf_len(c->input)) > 0) {
			if (c->datagram) {
				if (len > 0) {
					u_char *data;
					size_t dlen;

					if ((r = sshbuf_get_string(c->input,
					    &data, &dlen)) != 0)
						CHANNEL_BUFFER_ERROR(c, r);
					if (dlen > c->remote_window ||
					    dlen > c->remote_maxpacket) {
						debug("channel %u: datagram "
						    "too big for channel",
						    c->self);
						free(data);
						continue;
					}
					if ((r = sshpkt_start(ssh,
					    SSH2_MSG_CHANNEL_DATA)) != 0 ||
					    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
					    (r = sshpkt_put_string(ssh, data, dlen)) != 0 ||
					    (r = sshpkt_send(ssh)) != 0)
						CHANNEL_PACKET_ERROR(c, r);
					c->remote_window -= dlen + 4;
					free(data);
				}
				continue;
			}
			/*
			 * Send some data for the other side over the secure
			 * connection.
			 */
			if (compat20) {
				if (len > c->remote_window)
					len = c->remote_window;
				if (len > c->remote_maxpacket)
					len = c->remote_maxpacket;
			} else {
				if (ssh_packet_is_interactive(ssh)) {
					if (len > 1024)
						len = 512;
				} else {
					/* Keep the packets at reasonable size. */
					if (len > ssh_packet_get_maxsize(ssh)/2)
						len = ssh_packet_get_maxsize(ssh)/2;
				}
			}
			if (len > 0) {
				if ((r = sshpkt_start(ssh, compat20 ?
				    SSH2_MSG_CHANNEL_DATA : SSH_MSG_CHANNEL_DATA)) != 0 ||
				    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
				    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->input),
				    len)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					CHANNEL_PACKET_ERROR(c, r);
				if ((r = sshbuf_consume(c->input, len)) != 0)
					CHANNEL_BUFFER_ERROR(c, r);
				c->remote_window -= len;
			}
		} else if (c->istate == CHAN_INPUT_WAIT_DRAIN) {
			if (compat13)
				fatal("cannot happen: istate == INPUT_WAIT_DRAIN for proto 1.3");
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data: send IEOF.
			 * hack for extended data: delay EOF if EFD still in use.
			 */
			if (CHANNEL_EFD_INPUT_ACTIVE(c))
				debug2("channel %u: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			else
				chan_ibuf_empty(c);
		}
		/* Send extended data, i.e. stderr */
		if (compat20 &&
		    !(c->flags & CHAN_EOF_SENT) &&
		    c->remote_window > 0 &&
		    (len = sshbuf_len(c->extended)) > 0 &&
		    c->extended_usage == CHAN_EXTENDED_READ) {
			debug2("channel %u: rwin %u elen %zu euse %d",
			    c->self, c->remote_window, sshbuf_len(c->extended),
			    c->extended_usage);
			if (len > c->remote_window)
				len = c->remote_window;
			if (len > c->remote_maxpacket)
				len = c->remote_maxpacket;
			if ((r = sshpkt_start(ssh,
			    SSH2_MSG_CHANNEL_EXTENDED_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
			    (r = sshpkt_put_string(ssh,
			    sshbuf_ptr(c->extended), len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				CHANNEL_PACKET_ERROR(c, r);
			if ((r = sshbuf_consume(c->extended, len)) != 0)
				CHANNEL_BUFFER_ERROR(c, r);
			c->remote_window -= len;
			debug2("channel %u: sent ext data %d", c->self, len);
		}
	}
}


/* -- protocol input */

/* ARGSUSED */
int
channel_input_data(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int32_t id;
	const u_char *data;
	size_t data_len;
	u_int win_len;
	Channel *c;

	/* Get the channel number and verify it. */
	if ((r = sshpkt_get_u32(ssh, &id)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);
	if (c == NULL)
		ssh_packet_disconnect(ssh,
		    "Received data for nonexistent channel %u.", id);
	if (c->ssh != ssh)
		fatal("internal error (inconsistent ssh context)");

	/* Ignore any data for non-open channels (might happen on close) */
	if (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		return 0;

	/* Get the data. */
	if ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0)
		CHANNEL_PACKET_ERROR(c, r);
	win_len = data_len;
	if (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * Ignore data for protocol > 1.3 if output end is no longer open.
	 * For protocol 2 the sending side is reducing its window as it sends
	 * data, so we must 'fake' consumption of the data in order to ensure
	 * that window updates are sent back.  Otherwise the connection might
	 * deadlock.
	 */
	if (!compat13 && c->ostate != CHAN_OUTPUT_OPEN) {
		if (compat20) {
			c->local_window -= win_len;
			c->local_consumed += win_len;
		}
		return 0;
	}

	if (compat20) {
		if (win_len > c->local_maxpacket) {
			logit("channel %u: rcvd big packet %d, maxpack %d",
			    c->self, win_len, c->local_maxpacket);
		}
		if (win_len > c->local_window) {
			logit("channel %u: rcvd too much data %d, win %d",
			    c->self, win_len, c->local_window);
			return 0;
		}
		c->local_window -= win_len;
	}
	if (c->datagram)
		r = sshbuf_put_string(c->output, data, data_len);
	else
		r = sshbuf_put(c->output, data, data_len);
	if (r != 0)
		CHANNEL_BUFFER_ERROR(c, r);
	if ((r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(c, r);
	return 0;
}

/* ARGSUSED */
int
channel_input_extended_data(int type, u_int32_t seq, struct ssh *ssh)
{
	u_int id;
	int r;
	u_char *data;
	size_t data_len;
	u_int tcode;
	Channel *c;

	/* Get the channel number and verify it. */
	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &tcode)) != 0 ||
	    (r = sshpkt_get_string(ssh, &data, &data_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);

	if (c == NULL)
		ssh_packet_disconnect(ssh,
		    "Received extended_data for bad channel %d.", id);
	if (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %u: ext data for non open", id);
		return 0;
	}
	if (c->flags & CHAN_EOF_RCVD) {
		if (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %u: accepting ext data after eof", id);
		else
			ssh_packet_disconnect(ssh, "Received extended_data after EOF "
			    "on channel %d.", id);
	}
	if (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %u: bad ext data", c->self);
		return 0;
	}
	if (data_len > c->local_window) {
		logit("channel %u: rcvd too much extended_data %zu, win %d",
		    c->self, data_len, c->local_window);
		free(data);
		return 0;
	}
	debug2("channel %u: rcvd ext data %zu", c->self, data_len);
	c->local_window -= data_len;
	if ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		CHANNEL_BUFFER_ERROR(c, r);
	free(data);
	return 0;
}

/* ARGSUSED */
int
channel_input_ieof(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int id;
	Channel *c;

	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);
	if (c == NULL)
		ssh_packet_disconnect(ssh,
		    "Received ieof for nonexistent channel %d.", id);
	chan_rcvd_ieof(c);

	/* XXX force input close */
	if (c->force_drain && c->istate == CHAN_INPUT_OPEN) {
		debug("channel %u: FORCE input drain", c->self);
		c->istate = CHAN_INPUT_WAIT_DRAIN;
		if (sshbuf_len(c->input) == 0)
			chan_ibuf_empty(c);
	}
	return 0;
}

/* ARGSUSED */
int
channel_input_close(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int id;
	Channel *c;

	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);
	if (c == NULL)
		ssh_packet_disconnect(ssh,
		    "Received close for nonexistent channel %d.", id);

	/*
	 * Send a confirmation that we have closed the channel and no more
	 * data is coming for it.
	 */
	if ((r = sshpkt_start(ssh, SSH_MSG_CHANNEL_CLOSE_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		CHANNEL_PACKET_ERROR(c, r);

	/*
	 * If the channel is in closed state, we have sent a close request,
	 * and the other side will eventually respond with a confirmation.
	 * Thus, we cannot free the channel here, because then there would be
	 * no-one to receive the confirmation.  The channel gets freed when
	 * the confirmation arrives.
	 */
	if (c->type != SSH_CHANNEL_CLOSED) {
		/*
		 * Not a closed channel - mark it as draining, which will
		 * cause it to be freed later.
		 */
		sshbuf_reset(c->input);
		c->type = SSH_CHANNEL_OUTPUT_DRAINING;
	}
	return 0;
}

/* proto version 1.5 overloads CLOSE_CONFIRMATION with OCLOSE */
/* ARGSUSED */
int
channel_input_oclose(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int id;
	Channel *c;

	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);
	if (c == NULL)
		ssh_packet_disconnect(ssh,
		    "Received oclose for nonexistent channel %d.", id);
	chan_rcvd_oclose(c);
	return 0;
}

/* ARGSUSED */
int
channel_input_close_confirmation(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int id;
	Channel *c;

	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);
	if (c == NULL)
		ssh_packet_disconnect(ssh, "Received close confirmation for "
		    "out-of-range channel %d.", id);
	if (c->type != SSH_CHANNEL_CLOSED && c->type != SSH_CHANNEL_ABANDONED)
		ssh_packet_disconnect(ssh, "Received close confirmation for "
		    "non-closed channel %d (type %d).", id, c->type);
	channel_free(c);
	return 0;
}

/* ARGSUSED */
int
channel_input_open_confirmation(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int id, remote_id;
	Channel *c;

	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_id)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);
	if (c==NULL || c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", id);
	/* Record the remote channel number and mark that the channel is now open. */
	c->remote_id = remote_id;
	c->type = SSH_CHANNEL_OPEN;

	if (compat20) {
		if ((r = sshpkt_get_u32(ssh, &c->remote_window)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &c->remote_maxpacket)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
		if (c->open_confirm) {
			debug2("callback start");
			c->open_confirm(c->self, 1, c->open_confirm_ctx);
			debug2("callback done");
		}
		debug2("channel %u: open confirm rwindow %u rmax %u", c->self,
		    c->remote_window, c->remote_maxpacket);
	} else {
		if ((r = sshpkt_get_end(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
	}
	return 0;
}

static char *
reason2txt(u_int reason)
{
	switch (reason) {
	case SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		return "administratively prohibited";
	case SSH2_OPEN_CONNECT_FAILED:
		return "connect failed";
	case SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		return "unknown channel type";
	case SSH2_OPEN_RESOURCE_SHORTAGE:
		return "resource shortage";
	}
	return "unknown reason";
}

/* ARGSUSED */
int
channel_input_open_failure(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int id, reason;
	char *msg = NULL, *lang = NULL;
	Channel *c;

	if ((r = sshpkt_get_u32(ssh, &id)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_lookup(id);

	if (c==NULL || c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", id);
	if (compat20) {
		if ((r = sshpkt_get_u32(ssh, &reason)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
		if (!(ssh->compat & SSH_BUG_OPENFAILURE)) {
			if ((r = sshpkt_get_cstring(ssh, &msg, NULL)) != 0 ||
			    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
				CHANNEL_PACKET_ERROR(c, r);
		}
		logit("channel %u: open failed: %s%s%s", id,
		    reason2txt(reason), msg ? ": ": "", msg ? msg : "");
		free(msg);
		free(lang);
		if (c->open_confirm) {
			debug2("callback start");
			c->open_confirm(c->self, 0, c->open_confirm_ctx);
			debug2("callback done");
		}
	}
	if ((r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(c, r);
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(c);
	return 0;
}

/* ARGSUSED */
int
channel_input_window_adjust(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c;
	int r;
	u_int id, adjust;

	if (!compat20)
		return 0;

	/* Get the channel number and verify it. */
	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);

	c = channel_lookup(id);
	if (c == NULL) {
		logit("Received window adjust for non-open channel %d.", id);
		return 0;
	}
	debug2("channel %u: rcvd adjust %u", id, adjust);
	c->remote_window += adjust;
	return 0;
}

/* ARGSUSED */
int
channel_input_port_open(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c = NULL;
	u_int host_port;
	char *host, *originator_string;
	int r;
	u_int remote_id;

	if ((r = sshpkt_get_u32(ssh, &remote_id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &host, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &host_port)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);

	if (ssh_packet_get_protocol_flags(ssh) & SSH_PROTOFLAG_HOST_IN_FWD_OPEN) {
		if ((r = sshpkt_get_cstring(ssh, &originator_string, NULL)) != 0)
			CHANNEL_PACKET_ERROR(NULL, r);
	} else {
		originator_string = xstrdup("unknown (remote did not supply name)");
	}
	if ((r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	c = channel_connect_to(ssh, host, host_port, "connected socket",
	    originator_string);
	free(originator_string);
	free(host);
	if (c == NULL) {
		if ((r = sshpkt_start(ssh, SSH_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
	} else
		c->remote_id = remote_id;
	return 0;
}

/* ARGSUSED */
int
channel_input_status_confirm(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c;
	struct channel_confirm *cc;
	int r;
	u_int id;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);

	debug2("channel_input_status_confirm: type %d id %d", type, id);

	if ((c = channel_lookup(id)) == NULL) {
		logit("channel_input_status_confirm: %d: unknown", id);
		return 0;
	}	
	if ((cc = TAILQ_FIRST(&c->status_confirms)) == NULL)
		return 0;
	cc->cb(type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	bzero(cc, sizeof(*cc));
	free(cc);
	return 0;
}

/* -- tcp forwarding */

void
channel_set_af(int af)
{
	IPv4or6 = af;
}


/*
 * Determine whether or not a port forward listens to loopback, the
 * specified address or wildcard. On the client, a specified bind
 * address will always override gateway_ports. On the server, a
 * gateway_ports of 1 (``yes'') will override the client's specification
 * and force a wildcard bind, whereas a value of 2 (``clientspecified'')
 * will bind to whatever address the client asked for.
 *
 * Special-case listen_addrs are:
 *
 * "0.0.0.0"               -> wildcard v4/v6 if SSH_OLD_FORWARD_ADDR
 * "" (empty string), "*"  -> wildcard v4/v6
 * "localhost"             -> loopback v4/v6
 */
static const char *
channel_fwd_bind_addr(struct ssh *ssh, const char *listen_addr, int *wildcardp,
    int is_client, int gateway_ports)
{
	const char *addr = NULL;
	int wildcard = 0;

	if (listen_addr == NULL) {
		/* No address specified: default to gateway_ports setting */
		if (gateway_ports)
			wildcard = 1;
	} else if (gateway_ports || is_client) {
		if (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && gateway_ports == 1))
			wildcard = 1;
		else if (strcmp(listen_addr, "localhost") != 0)
			addr = listen_addr;
	}
	if (wildcardp != NULL)
		*wildcardp = wildcard;
	return addr;
}

static int
channel_setup_fwd_listener(struct ssh *ssh, int type, const char *listen_addr,
    u_short listen_port, int *allocated_listen_port,
    const char *host_to_connect, u_short port_to_connect, int gateway_ports)
{
	Channel *c;
	int sock, r, success = 0, wildcard = 0, is_client;
	struct addrinfo hints, *ai, *aitop;
	const char *host, *addr;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
	    listen_addr : host_to_connect;
	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	if (host == NULL) {
		error("No forward host name.");
		return 0;
	}
	if (strlen(host) >= NI_MAXHOST) {
		error("Forward host name too long.");
		return 0;
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, listen_addr, &wildcard,
	    is_client, gateway_ports);
	debug3("channel_setup_fwd_listener: type %d wildcard %d addr %s",
	    type, wildcard, (addr == NULL) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%d", listen_port);
	if ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		if (addr == NULL) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh,
			    "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} else {
			error("channel_setup_fwd_listener: "
			    "getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		return 0;
	}
	if (allocated_listen_port != NULL)
		*allocated_listen_port = 0;
	for (ai = aitop; ai; ai = ai->ai_next) {
		switch (ai->ai_family) {
		case AF_INET:
			lport_p = &((struct sockaddr_in *)ai->ai_addr)->
			    sin_port;
			break;
		case AF_INET6:
			lport_p = &((struct sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			break;
		default:
			continue;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		if (type == SSH_CHANNEL_RPORT_LISTENER && listen_port == 0 &&
		    allocated_listen_port != NULL && *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, sizeof(ntop),
		    strport, sizeof(strport), NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error("channel_setup_fwd_listener: getnameinfo failed");
			continue;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			continue;
		}

		channel_set_reuseaddr(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			/* address can be in use ipv6 address is already bound */
			verbose("bind: %.100s", strerror(errno));
			close(sock);
			continue;
		}
		/* Start listening for connections on the socket. */
		if (listen(sock, SSH_LISTEN_BACKLOG) < 0) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			continue;
		}

		/*
		 * listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		if (type == SSH_CHANNEL_RPORT_LISTENER && listen_port == 0 &&
		    allocated_listen_port != NULL &&
		    *allocated_listen_port == 0) {
			*allocated_listen_port = get_sock_port(sock, 1);
			debug("Allocated listen port %d",
			    *allocated_listen_port);
		}

		/* Allocate a channel number for the socket. */
		c = channel_new(ssh, "port listener", type, sock, sock, -1,
		    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		c->path = xstrdup(host);
		c->host_port = port_to_connect;
		c->listening_addr = addr == NULL ? NULL : xstrdup(addr);
		if (listen_port == 0 && allocated_listen_port != NULL &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		else
			c->listening_port = listen_port;
		success = 1;
	}
	if (success == 0)
		error("channel_setup_fwd_listener: cannot listen to port: %d",
		    listen_port);
	freeaddrinfo(aitop);
	return success;
}

int
channel_cancel_rport_listener(const char *host, u_short port)
{
	u_int i;
	int found = 0;

	for (i = 0; i < channels_alloc; i++) {
		Channel *c = channels[i];
		if (c == NULL || c->type != SSH_CHANNEL_RPORT_LISTENER)
			continue;
		if (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2("%s: close channel %d", __func__, i);
			channel_free(c);
			found = 1;
		}
	}

	return (found);
}

int
channel_cancel_lport_listener(struct ssh *ssh, const char *lhost, u_short lport,
    int cport, int gateway_ports)
{
	u_int i;
	int found = 0;
	const char *addr = channel_fwd_bind_addr(ssh, lhost, NULL, 1,
	    gateway_ports);

	for (i = 0; i < channels_alloc; i++) {
		Channel *c = channels[i];
		if (c == NULL || c->type != SSH_CHANNEL_PORT_LISTENER)
			continue;
		if (c->listening_port != lport || c->ssh != ssh)
			continue;
		if (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			if (c->host_port == 0)
				continue;
		} else {
			if (c->host_port != cport)
				continue;
		}
		if ((c->listening_addr == NULL && addr != NULL) ||
		    (c->listening_addr != NULL && addr == NULL))
			continue;
		if (addr == NULL || strcmp(c->listening_addr, addr) == 0) {
			debug2("%s: close channel %d", __func__, i);
			channel_free(c);
			found = 1;
		}
	}

	return (found);
}

/* protocol local port fwd, used by ssh (and sshd in v1) */
int
channel_setup_local_fwd_listener(struct ssh *ssh, const char *listen_host,
    u_short listen_port, const char *host_to_connect, u_short port_to_connect,
    int gateway_ports)
{
	return channel_setup_fwd_listener(ssh, SSH_CHANNEL_PORT_LISTENER,
	    listen_host, listen_port, NULL, host_to_connect, port_to_connect,
	    gateway_ports);
}

/* protocol v2 remote port fwd, used by sshd */
int
channel_setup_remote_fwd_listener(struct ssh *ssh, const char *listen_address,
    u_short listen_port, int *allocated_listen_port, int gateway_ports)
{
	return channel_setup_fwd_listener(ssh, SSH_CHANNEL_RPORT_LISTENER,
	    listen_address, listen_port, allocated_listen_port,
	    NULL, 0, gateway_ports);
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
static const char *
channel_rfwd_bind_host(struct ssh *ssh, const char *listen_host)
{
	if (listen_host == NULL) {
		if (ssh->compat & SSH_BUG_RFWD_ADDR)
			return "127.0.0.1";
		else
			return "localhost";
	} else if (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		if (ssh->compat & SSH_BUG_RFWD_ADDR)
			return "0.0.0.0";
		else
			return "";
	} else
		return listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permitted_opens().
 */
int
channel_request_remote_forwarding(struct ssh *ssh, const char *listen_host,
    u_short listen_port, const char *host_to_connect, u_short port_to_connect)
{
	int r, type, success = 0, idx = -1;

	/* Send the forward request to the remote side. */
	if (compat20) {
		if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 ||	/* boolean: want reply */
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(ssh, listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, listen_port)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		ssh_packet_write_wait(ssh);
		/* Assume that server accepts the request */
		success = 1;
	} else {
		if ((r = sshpkt_start(ssh, SSH_CMSG_PORT_FORWARD_REQUEST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, listen_port)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, host_to_connect)) != 0 ||
		    (r = sshpkt_put_u32(ssh, port_to_connect)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		ssh_packet_write_wait(ssh);

		/* Wait for response from the remote side. */
		type = ssh_packet_read(ssh);
		switch (type) {
		case SSH_SMSG_SUCCESS:
			success = 1;
			break;
		case SSH_SMSG_FAILURE:
			break;
		default:
			/* Unknown packet */
			ssh_packet_disconnect(ssh,
			    "Protocol error for port forward request:"
			    "received packet type %d.", type);
		}
	}
	if (success) {
		/* Record that connection to this host/port is permitted. */
		permitted_opens = xrealloc(permitted_opens,
		    num_permitted_opens + 1, sizeof(*permitted_opens));
		idx = num_permitted_opens++;
		permitted_opens[idx].host_to_connect = xstrdup(host_to_connect);
		permitted_opens[idx].port_to_connect = port_to_connect;
		permitted_opens[idx].listen_port = listen_port;
	}
	return (idx);
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
int
channel_request_rforward_cancel(struct ssh *ssh, const char *host, u_short port)
{
	int r, i;

	if (!compat20)
		return -1;

	for (i = 0; i < num_permitted_opens; i++) {
		if (permitted_opens[i].host_to_connect != NULL &&
		    permitted_opens[i].listen_port == port)
			break;
	}
	if (i >= num_permitted_opens) {
		debug("%s: requested forward not found", __func__);
		return -1;
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(ssh, host)))
	    != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	permitted_opens[i].listen_port = 0;
	permitted_opens[i].port_to_connect = 0;
	free(permitted_opens[i].host_to_connect);
	permitted_opens[i].host_to_connect = NULL;

	return 0;
}

/*
 * This is called after receiving CHANNEL_FORWARDING_REQUEST.  This initates
 * listening for the port, and sends back a success reply (or disconnect
 * message if there was an error).
 */
int
channel_input_port_forward_request(struct ssh *ssh, int is_root,
    int gateway_ports)
{
	u_int port, host_port;
	int r, success = 0;
	char *hostname;

	/* Get arguments from the packet. */
	if ((r = sshpkt_get_u32(ssh, &port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &hostname, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &host_port)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	/*
	 * Check that an unprivileged user is not trying to forward a
	 * privileged port.
	 */
	if ((u_short)port < IPPORT_RESERVED && !is_root)
		ssh_packet_disconnect(ssh,
		    "Requested forwarding of port %d but user is not root.",
		    port);
	if (host_port == 0)
		ssh_packet_disconnect(ssh, "Dynamic forwarding denied.");

	/* Initiate forwarding */
	success = channel_setup_local_fwd_listener(ssh, NULL, port, hostname,
	    host_port, gateway_ports);

	/* Free the argument string. */
	free(hostname);

	return (success ? 0 : -1);
}

/*
 * Permits opening to any host/port if permitted_opens[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
void
channel_permit_all_opens(void)
{
	if (num_permitted_opens == 0)
		all_opens_permitted = 1;
}

void
channel_add_permitted_opens(char *host, int port)
{
	debug("allow port forwarding to host %s port %d", host, port);

	permitted_opens = xrealloc(permitted_opens,
	    num_permitted_opens + 1, sizeof(*permitted_opens));
	permitted_opens[num_permitted_opens].host_to_connect = xstrdup(host);
	permitted_opens[num_permitted_opens].port_to_connect = port;
	num_permitted_opens++;

	all_opens_permitted = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
void
channel_update_permitted_opens(struct ssh *ssh, int idx, int newport)
{
	if (idx < 0 || idx >= num_permitted_opens) {
		debug("channel_update_permitted_opens: index out of range:"
		    " %d num_permitted_opens %d", idx, num_permitted_opens);
		return;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    permitted_opens[idx].host_to_connect,
	    permitted_opens[idx].port_to_connect);
	if (newport >= 0)  {
		permitted_opens[idx].listen_port = 
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	} else {
		permitted_opens[idx].listen_port = 0;
		permitted_opens[idx].port_to_connect = 0;
		free(permitted_opens[idx].host_to_connect);
		permitted_opens[idx].host_to_connect = NULL;
	}
}

int
channel_add_adm_permitted_opens(char *host, int port)
{
	debug("config allows port forwarding to host %s port %d", host, port);

	permitted_adm_opens = xrealloc(permitted_adm_opens,
	    num_adm_permitted_opens + 1, sizeof(*permitted_adm_opens));
	permitted_adm_opens[num_adm_permitted_opens].host_to_connect
	     = xstrdup(host);
	permitted_adm_opens[num_adm_permitted_opens].port_to_connect = port;
	return ++num_adm_permitted_opens;
}

void
channel_disable_adm_local_opens(void)
{
	channel_clear_adm_permitted_opens();
	permitted_adm_opens = xmalloc(sizeof(*permitted_adm_opens));
	permitted_adm_opens[num_adm_permitted_opens].host_to_connect = NULL;
	num_adm_permitted_opens = 1;
}

void
channel_clear_permitted_opens(void)
{
	int i;

	for (i = 0; i < num_permitted_opens; i++)
		free(permitted_opens[i].host_to_connect);
	free(permitted_opens);
	permitted_opens = NULL;
	num_permitted_opens = 0;
}

void
channel_clear_adm_permitted_opens(void)
{
	int i;

	for (i = 0; i < num_adm_permitted_opens; i++)
		free(permitted_adm_opens[i].host_to_connect);
	free(permitted_adm_opens);
	permitted_adm_opens = NULL;
	num_adm_permitted_opens = 0;
}

void
channel_print_adm_permitted_opens(void)
{
	int i;

	printf("permitopen");
	if (num_adm_permitted_opens == 0) {
		printf(" any\n");
		return;
	}
	for (i = 0; i < num_adm_permitted_opens; i++)
		if (permitted_adm_opens[i].host_to_connect == NULL)
			printf(" none");
		else
			printf(" %s:%d", permitted_adm_opens[i].host_to_connect,
			    permitted_adm_opens[i].port_to_connect);
	printf("\n");
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
int
permitopen_port(const char *p)
{
	int port;

	if (strcmp(p, "*") == 0)
		return FWD_PERMIT_ANY_PORT;
	if ((port = a2port(p)) > 0)
		return port;
	return -1;
}

static int
port_match(u_short allowedport, u_short requestedport)
{
	if (allowedport == FWD_PERMIT_ANY_PORT ||
	    allowedport == requestedport)
		return 1;
	return 0;
}

/* Try to start non-blocking connect to next host in cctx list */
static int
connect_next(struct channel_connect *cctx)
{
	int sock, saved_errno;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	for (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		if (cctx->ai->ai_family != AF_INET &&
		    cctx->ai->ai_family != AF_INET6)
			continue;
		if (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
		    ntop, sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error("connect_next: getnameinfo failed");
			continue;
		}
		if ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			if (cctx->ai->ai_next == NULL)
				error("socket: %.100s", strerror(errno));
			else
				verbose("socket: %.100s", strerror(errno));
			continue;
		}
		if (set_nonblock(sock) == -1)
			fatal("%s: set_nonblock(%d)", __func__, sock);
		if (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug("connect_next: host %.100s ([%.100s]:%s): "
			    "%.100s", cctx->host, ntop, strport,
			    strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			continue;	/* fail -- try next */
		}
		debug("connect_next: host %.100s ([%.100s]:%s) "
		    "in progress, fd=%d", cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		set_nodelay(sock);
		return sock;
	}
	return -1;
}

static void
channel_connect_ctx_free(struct channel_connect *cctx)
{
	free(cctx->host);
	if (cctx->aitop)
		freeaddrinfo(cctx->aitop);
	bzero(cctx, sizeof(*cctx));
	cctx->host = NULL;
	cctx->ai = cctx->aitop = NULL;
}

/* Return CONNECTING channel to remote host, port */
static Channel *
connect_to(struct ssh *ssh, const char *host, u_short port, char *ctype,
    char *rname)
{
	struct addrinfo hints;
	int gaierr;
	int sock = -1;
	char strport[NI_MAXSERV];
	struct channel_connect cctx;
	Channel *c;

	memset(&cctx, 0, sizeof(cctx));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%d", port);
	if ((gaierr = getaddrinfo(host, strport, &hints, &cctx.aitop)) != 0) {
		error("connect_to %.100s: unknown host (%s)", host,
		    ssh_gai_strerror(gaierr));
		return NULL;
	}

	cctx.host = xstrdup(host);
	cctx.port = port;
	cctx.ai = cctx.aitop;

	if ((sock = connect_next(&cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    host, port, strerror(errno));
		channel_connect_ctx_free(&cctx);
		return NULL;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->connect_ctx = cctx;
	return c;
}

Channel *
channel_connect_by_listen_address(struct ssh *ssh, u_short listen_port,
    char *ctype, char *rname)
{
	int i;

	for (i = 0; i < num_permitted_opens; i++) {
		if (permitted_opens[i].host_to_connect != NULL &&
		    port_match(permitted_opens[i].listen_port, listen_port)) {
			return connect_to(ssh,
			    permitted_opens[i].host_to_connect,
			    permitted_opens[i].port_to_connect, ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	return NULL;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to(struct ssh *ssh, const char *host, u_short port, char *ctype,
    char *rname)
{
	int i, permit, permit_adm = 1;

	permit = all_opens_permitted;
	if (!permit) {
		for (i = 0; i < num_permitted_opens; i++)
			if (permitted_opens[i].host_to_connect != NULL &&
			    port_match(permitted_opens[i].port_to_connect, port) &&
			    strcmp(permitted_opens[i].host_to_connect, host) == 0)
				permit = 1;
	}

	if (num_adm_permitted_opens > 0) {
		permit_adm = 0;
		for (i = 0; i < num_adm_permitted_opens; i++)
			if (permitted_adm_opens[i].host_to_connect != NULL &&
			    port_match(permitted_adm_opens[i].port_to_connect, port) &&
			    strcmp(permitted_adm_opens[i].host_to_connect, host)
			    == 0)
				permit_adm = 1;
	}

	if (!permit || !permit_adm) {
		logit("Received request to connect to host %.100s port %d, "
		    "but the request was denied.", host, port);
		return NULL;
	}
	return connect_to(ssh, host, port, ctype, rname);
}

void
channel_send_window_changes(void)
{
	struct ssh *ssh;
	u_int i;
	int r;
	struct winsize ws;

	for (i = 0; i < channels_alloc; i++) {
		if (channels[i] == NULL || !channels[i]->client_tty ||
		    channels[i]->type != SSH_CHANNEL_OPEN)
			continue;
		if (ioctl(channels[i]->rfd, TIOCGWINSZ, &ws) < 0)
			continue;
		ssh = channels[i]->ssh;
		channel_request_start(i, "window-change", 0);
		if ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
	}
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
int
x11_create_display_inet(struct ssh *ssh, int x11_display_offset,
    int x11_use_localhost, int single_connection, u_int *display_numberp,
    u_int **chanids)
{
	Channel *nc = NULL;
	int display_number, sock;
	u_short port;
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr, n, num_socks = 0, socks[NUM_SOCKS];

	if (chanids == NULL)
		return -1;

	for (display_number = x11_display_offset;
	    display_number < MAX_DISPLAYS;
	    display_number++) {
		port = 6000 + display_number;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, sizeof strport, "%d", port);
		if ((gaierr = getaddrinfo(NULL, strport, &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			return -1;
		}
		for (ai = aitop; ai; ai = ai->ai_next) {
			if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
				continue;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			if (sock < 0) {
				error("socket: %.100s", strerror(errno));
				freeaddrinfo(aitop);
				return -1;
			}
			channel_set_reuseaddr(sock);
			if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
				debug2("bind port %d: %.100s", port, strerror(errno));
				close(sock);

				for (n = 0; n < num_socks; n++) {
					close(socks[n]);
				}
				num_socks = 0;
				break;
			}
			socks[num_socks++] = sock;
			if (num_socks == NUM_SOCKS)
				break;
		}
		freeaddrinfo(aitop);
		if (num_socks > 0)
			break;
	}
	if (display_number >= MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		return -1;
	}
	/* Start listening for connections on the socket. */
	for (n = 0; n < num_socks; n++) {
		sock = socks[n];
		if (listen(sock, SSH_LISTEN_BACKLOG) < 0) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			return -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(num_socks + 1, sizeof(**chanids));
	for (n = 0; n < num_socks; n++) {
		sock = socks[n];
		nc = channel_new(ssh, "x11 listener",
		    SSH_CHANNEL_X11_LISTENER, sock, sock, -1,
		    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
		    0, "X11 inet listener", 1);
		nc->single_connection = single_connection;
		(*chanids)[n] = nc->self;
	}
	(*chanids)[n] = CHANNEL_ID_NONE;

	/* Return the display number for the DISPLAY environment variable. */
	*display_numberp = display_number;
	return (0);
}

static int
connect_local_xsocket(u_int dnr)
{
	int sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		error("socket: %.100s", strerror(errno));
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof addr.sun_path, _PATH_UNIX_X, dnr);
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
		return sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	return -1;
}

int
x11_connect_display(void)
{
	u_int display_number;
	const char *display;
	char buf[1024], *cp;
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	if (!display) {
		error("DISPLAY not set.");
		return -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	if (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		if (sscanf(strrchr(display, ':') + 1, "%u", &display_number) != 1) {
			error("Could not parse display number from DISPLAY: %.100s",
			    display);
			return -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_number);
		if (sock < 0)
			return -1;

		/* OK, we now have a connection to the display. */
		return sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, sizeof(buf));
	cp = strchr(buf, ':');
	if (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		return -1;
	}
	*cp = 0;
	/* buf now contains the host name.  But first we parse the display number. */
	if (sscanf(cp + 1, "%u", &display_number) != 1) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		return -1;
	}

	/* Look up the host address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%u", 6000 + display_number);
	if ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		return -1;
	}
	for (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) {
			debug2("socket: %.100s", strerror(errno));
			continue;
		}
		/* Connect it to the display. */
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			debug2("connect %.100s port %u: %.100s", buf,
			    6000 + display_number, strerror(errno));
			close(sock);
			continue;
		}
		/* Success */
		break;
	}
	freeaddrinfo(aitop);
	if (!ai) {
		error("connect %.100s port %u: %.100s", buf, 6000 + display_number,
		    strerror(errno));
		return -1;
	}
	set_nodelay(sock);
	return sock;
}

/*
 * This is called when SSH_SMSG_X11_OPEN is received.  The packet contains
 * the remote channel number.  We should do whatever we want, and respond
 * with either SSH_MSG_OPEN_CONFIRMATION or SSH_MSG_OPEN_FAILURE.
 */

/* ARGSUSED */
int
x11_input_open(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c = NULL;
	int r, sock = 0;
	u_int remote_id;
	char *remote_host;

	debug("Received X11 open request.");

	if ((r = sshpkt_get_u32(ssh, &remote_id)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);

	if (ssh_packet_get_protocol_flags(ssh) &
	    SSH_PROTOFLAG_HOST_IN_FWD_OPEN) {
		if ((r = sshpkt_get_cstring(ssh, &remote_host, NULL)) != 0)
			CHANNEL_PACKET_ERROR(NULL, r);
	} else {
		remote_host = xstrdup("unknown (remote did not supply name)");
	}
	if ((r = sshpkt_get_end(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);

	/* Obtain a connection to the real X display. */
	sock = x11_connect_display();
	if (sock != -1) {
		/* Allocate a channel for this connection. */
		c = channel_new(ssh, "connected x11 socket",
		    SSH_CHANNEL_X11_OPEN, sock, sock, -1, 0, 0, 0,
		    remote_host, 1);
		c->remote_id = remote_id;
		c->force_drain = 1;
	}
	free(remote_host);
	if (c == NULL) {
		/* Send refusal to the remote host. */
		if ((r = sshpkt_start(ssh, SSH_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(NULL, r);
	} else {
		/* Send a confirmation to the remote host. */
		if ((r = sshpkt_start(ssh,
		    SSH_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
		    (r = sshpkt_put_u32(ssh, remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			CHANNEL_PACKET_ERROR(c, r);
	}
	return 0;
}

/* dummy protocol handler that denies SSH-1 requests (agent/x11) */
/* ARGSUSED */
int
deny_input_open(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;
	u_int rchan;

	if ((r = sshpkt_get_u32(ssh, &rchan)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);

	switch (type) {
	case SSH_SMSG_AGENT_OPEN:
		error("Warning: ssh server tried agent forwarding.");
		break;
	case SSH_SMSG_X11_OPEN:
		error("Warning: ssh server tried X11 forwarding.");
		break;
	default:
		error("deny_input_open: type %d", type);
		break;
	}
	error("Warning: this is probably a break-in attempt by a malicious server.");
	if ((r = sshpkt_start(ssh, SSH_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	return 0;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
void
x11_request_forwarding_with_spoofing(struct ssh *ssh, int client_session_id,
    const char *disp, const char *proto, const char *data, int want_reply)
{
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, value;
	char *new_data;
	int screen_number;
	const char *cp;
	u_int32_t rnd = 0;
	int r;

	if (x11_saved_display == NULL)
		x11_saved_display = xstrdup(disp);
	else if (strcmp(disp, x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		return;
	}

	cp = strchr(disp, ':');
	if (cp)
		cp = strchr(cp, '.');
	if (cp)
		screen_number = (u_int)strtonum(cp + 1, 0, 400, NULL);
	else
		screen_number = 0;

	if (x11_saved_proto == NULL) {
		/* Save protocol name. */
		x11_saved_proto = xstrdup(proto);
		/*
		 * Extract real authentication data and generate fake data
		 * of the same length.
		 */
		x11_saved_data = xmalloc(data_len);
		x11_fake_data = xmalloc(data_len);
		for (i = 0; i < data_len; i++) {
			if (sscanf(data + 2 * i, "%2x", &value) != 1)
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			if (i % 4 == 0)
				rnd = arc4random();
			x11_saved_data[i] = value;
			x11_fake_data[i] = rnd & 0xff;
			rnd >>= 8;
		}
		x11_saved_data_len = data_len;
		x11_fake_data_len = data_len;
	}

	/* Convert the fake data into hex. */
	new_data = tohex(x11_fake_data, data_len);

	/* Send the request packet. */
	if (compat20) {
		channel_request_start(client_session_id, "x11-req", want_reply);
		if ((r = sshpkt_put_u8(ssh, 0)) != 0) /* single connection */
			CHANNEL_PACKET_ERROR(NULL, r);
	} else {
		if ((r = sshpkt_start(ssh, SSH_CMSG_X11_REQUEST_FORWARDING)) != 0)
			CHANNEL_PACKET_ERROR(NULL, r);
	}
	if ((r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_number)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	ssh_packet_write_wait(ssh);
	free(new_data);
}


/* -- agent forwarding */

/* Sends a message to the server to request authentication fd forwarding. */

void
auth_request_forwarding(struct ssh *ssh)
{
	int r;

	if ((r = sshpkt_start(ssh, SSH_CMSG_AGENT_REQUEST_FORWARDING)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		CHANNEL_PACKET_ERROR(NULL, r);
	ssh_packet_write_wait(ssh);
}
