/* $OpenBSD: $ */
/*
 * Copyright (c) 2012 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "ssh_api.h"
#include "log.h"
#include "misc.h"
#include "myproposal.h"
#include "readconf.h"
#include "authfile.h"
#include "err.h"
#include "sshbuf.h"

struct side {
	int fd;
	struct event input, output;
	struct ssh *ssh;
};
#define SESSION_CONNECTED	0x01
#define SESSION_NEEDS_FLUSH	0x02
struct session {
	struct side client, server;
	TAILQ_ENTRY(session) next;
	int flags;
};
Forward fwd;

void accept_cb(int, short, void *);
void connect_cb(int, short, void *);
void input_cb(int, short, void *);
void output_cb(int, short, void *);

int do_connect(const char *, int);
int do_listen(const char *, int);
void session_close(struct session *);
int ssh_packet_fwd(struct side *, struct side *);
int ssh_prepare_output(struct side *);
void usage(void);

uid_t original_real_uid;	/* XXX */
TAILQ_HEAD(, session) sessions;
struct kex_params kex_params;
int foreground;
int dump_packets;

#define BUFSZ 16*1024
struct sshkey *hostkey, *known_hostkey;

int
do_listen(const char *addr, int port)
{
	int sock, on = 1;
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	snprintf(strport, sizeof strport, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(addr, strport, &hints, &aitop) != 0) {
		error("getaddrinfo: fatal error");
		return -1;
	}
	sock = -1;
	for (ai = aitop; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if ((sock = socket(ai->ai_family, SOCK_STREAM, 0)) < 0)
			continue;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
		    sizeof(on)) == -1) {
			error("setsockopt: %s", strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}
		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			error("bind: %s", strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}
		if (listen(sock, 5) < 0) {
			error("listen: %s", strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(aitop);
	return sock;
}

int
do_connect(const char *addr, int port)
{
	struct addrinfo hints, *ai, *aitop;
	int gaierr;
	int sock = -1;
	char strport[NI_MAXSERV];
	snprintf(strport, sizeof strport, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", addr, gai_strerror(gaierr));
		return -1;
	}
	for (ai = aitop; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if ((sock = socket(ai->ai_family, SOCK_STREAM, 0)) < 0) {
			error("socket: %s", strerror(errno));
			continue;
		}
		if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
			error("fcntl connect F_SETFL: %s", strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0 &&
		    errno != EINPROGRESS) {
			error("connect(%s, %d): %s", addr, port, strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(aitop);
	if (!ai)
		return -1;
	return sock;
}

void
session_close(struct session *s)
{
	if (s->client.fd != -1)
		close(s->client.fd);
	if (s->server.fd != -1)
		close(s->server.fd);
	if (s->flags & SESSION_CONNECTED) {
		event_del(&s->client.input);
		event_del(&s->client.output);
		event_del(&s->server.input);
		event_del(&s->server.output);
		if (s->client.ssh) {
			ssh_free(s->client.ssh);
			s->client.ssh = NULL;
		}
		if (s->server.ssh) {
			ssh_free(s->server.ssh);
			s->server.ssh = NULL;
		}
		TAILQ_REMOVE(&sessions, s, next);
	}
	debug2("closing session %p", s);
	free(s);
}

void
accept_cb(int fd, short type, void *arg)
{
	struct event *ev = arg;
	struct session *s = NULL;
	socklen_t addrlen;
	struct sockaddr addr;
	int acceptfd = -1;

	if ((acceptfd = accept(fd, &addr, &addrlen)) < 0) {
		fatal("accept: %s", strerror(errno));
		goto fail;
	}
	if (fcntl(acceptfd, F_SETFL, O_NONBLOCK) < 0) {
		error("fcntl accepted F_SETFL: %s", strerror(errno));
		goto fail;
	}
	if ((s = calloc(1, sizeof(struct session))) == NULL) {
		error("calloc: %s", strerror(errno));
		goto fail;
	}
	s->server.fd = -1;
	s->client.fd = acceptfd;
	event_add(ev, NULL);
	addrlen = sizeof(addr);
	if ((s->server.fd = do_connect(fwd.connect_host, fwd.connect_port)) < 0) {
		error("do_connect() failed");
		goto fail;
	}
	event_set(&s->server.output, s->server.fd, EV_WRITE, connect_cb, s);
	event_add(&s->server.output, NULL);
	debug2("new session %p", s);
	return;
fail:
	if (acceptfd != -1)
		close(acceptfd);
	if (s)
		free(s);
}

void
connect_cb(int fd, short type, void *arg)
{
	struct session *s = arg;
	int soerr;
	int r;
	socklen_t sz = sizeof(soerr);

	event_del(&s->server.output);
	if (getsockopt(s->server.fd, SOL_SOCKET, SO_ERROR, &soerr, &sz) < 0) {
		soerr = errno;
		error("connect_cb: getsockopt: %s", strerror(errno));
	}
	if (soerr != 0)
		goto fail;
	memcpy(kex_params.proposal, myproposal, sizeof(kex_params.proposal));
	if ((r = ssh_init(&s->client.ssh, 1, &kex_params)) != 0) {
		error("could init client context: %s", ssh_err(r));
		goto fail;
	}
	if ((r = ssh_init(&s->server.ssh, 0, &kex_params)) != 0) {
		error("could init server context: %s", ssh_err(r));
		goto fail;
	}
	if ((r = ssh_add_hostkey(s->client.ssh, hostkey)) != 0) {
		error("could not load server hostkey: %s", ssh_err(r));
		goto fail;
	}
	if ((r = ssh_add_hostkey(s->server.ssh, known_hostkey)) !=  0) {
		error("could not load client known hostkey: %s", ssh_err(r));
		goto fail;
	}
	event_set(&s->client.input,  s->client.fd, EV_READ, input_cb, s);
	event_set(&s->client.output, s->client.fd, EV_WRITE, output_cb, s);
	event_set(&s->server.input,  s->server.fd, EV_READ, input_cb, s);
	event_set(&s->server.output, s->server.fd, EV_WRITE, output_cb, s);
	event_add(&s->server.input, NULL);
	event_add(&s->client.input, NULL);
	s->flags = SESSION_CONNECTED;
	TAILQ_INSERT_TAIL(&sessions, s, next);
	return;
 fail:
	close(s->server.fd);
	s->server.fd = -1;
	session_close(s);
	return;
}

/* schedule output event and return 1 if there is any output pending */
int
ssh_prepare_output(struct side *side)
{
	size_t len;

	ssh_output_ptr(side->ssh, &len);
	if (len) {
		debug3("output %zd for %d", len, side->fd);
		event_add(&side->output, NULL);
	}
	return len > 0;
}

int
ssh_packet_fwd(struct side *from, struct side *to)
{
	struct sshbuf *b;
	const u_char *data;
	u_char type;
	size_t len;
	int ret;

	if (!from->ssh || !to->ssh)
		return 0;
	for (;;) {
		if ((ret = ssh_packet_next(from->ssh, &type)) != 0)
			return ret;
		if (!type) {
			debug3("no packet on %d", from->fd);
			return 0;
		}
		data = ssh_packet_payload(from->ssh, &len);
		debug("ssh_packet_fwd %d->%d type %d len %zd",
		    from->fd, to->fd, type, len);
		if ((dump_packets && type != 50) ||
		    dump_packets > 1) {
			if ((b = sshbuf_from(data, len)) != NULL) {
				sshbuf_dump(b, stderr);
				sshbuf_free(b);
			}
		}
		if ((ret = ssh_packet_put(to->ssh, type, data, len)) != 0)
			return ret;
	}
}

void
input_cb(int fd, short type, void *arg)
{
	u_char buf[BUFSZ];
	struct session *s = arg;
	struct side *r, *w;
	ssize_t len;
	int pending, r1, r2;
	const char *tag;

	if (fd == s->client.fd) {
		tag = "client";
		r = &s->client;
		w = &s->server;
	} else {
		tag = "server";
		r = &s->server;
		w = &s->client;
	}
	debug2("input_cb %s fd %d", tag, fd);
	len = read(fd, buf, sizeof(buf));
	if (len < 0 && (errno == EINTR || errno == EAGAIN)) {
		event_add(&r->input, NULL);
	} else if (len <= 0) {
		debug("read %s failed fd %d len %zd", tag, fd, len);
		session_close(s);
		return;
	} else {
		debug2("read %s fd %d len %zd", tag, fd, len);
		event_add(&r->input, NULL);
		ssh_input_append(r->ssh, buf, len);
	}
	r1 = ssh_packet_fwd(r, w);
	r2 = ssh_packet_fwd(w, r);
	pending = ssh_prepare_output(r) + ssh_prepare_output(w);
	if (r1 || r1) {
		error("ssh_packet_fwd: %s/%s", ssh_err(r1), ssh_err(r2));
		if (pending)
			s->flags |= SESSION_NEEDS_FLUSH;
		else
			session_close(s);
	}
}

void
output_cb(int fd, short type, void *arg)
{
	struct session *s = arg;
	struct side *r, *w;
	ssize_t len;
	size_t olen;
	int pending;
	const char *tag;
	const u_char *obuf;

	if (fd == s->client.fd) {
		tag = "client";
		w = &s->client;
		r = &s->server;
	} else {
		tag = "server";
		w = &s->server;
		r = &s->client;
	}
	debug2("output_cb %s fd %d", tag, fd);
	obuf = ssh_output_ptr(w->ssh, &olen);
	if (olen > 0) {
		len = write(fd, obuf, olen);
		if (len < 0 && (errno == EINTR || errno == EAGAIN)) {
			event_add(&w->output, NULL);
		} else if (len <= 0) {
			debug("write %s failed fd %d len %zd", tag, fd, len);
			session_close(s);
			return;
		} else if ((size_t)len < olen) {
			debug("write %s partial fd %d len %zd olen %zd",
			    tag, fd, len, olen);
			ssh_output_consume(w->ssh, len);
		} else {
			debug2("write %s done fd %d", tag, fd);
			ssh_output_consume(w->ssh, len);
		}
	}
	if (!(s->flags & SESSION_NEEDS_FLUSH)) {
		ssh_packet_fwd(r, w);
		ssh_packet_fwd(w, r);
	}
	pending = ssh_prepare_output(r) + ssh_prepare_output(w);
	if ((s->flags & SESSION_NEEDS_FLUSH) && !pending) {
		debug("delayed close %p", s);
		s->flags &= ~SESSION_NEEDS_FLUSH;
		session_close(s);
	}
}

void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-dfh] [-L [laddr:]lport:saddr:sport]"
	    " [-C knownkey] [-S serverkey]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int ch, log_stderr = 1, fd, r;
	struct event ev;
	char *hostkey_file = NULL, *known_hostkey_file = NULL;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_VERBOSE;
	extern char *__progname;

	TAILQ_INIT(&sessions);

	while ((ch = getopt(argc, argv, "dfC:DL:S:")) != -1) {
		switch (ch) {
		case 'd':
			if (log_level == SYSLOG_LEVEL_VERBOSE)
				log_level = SYSLOG_LEVEL_DEBUG1;
			else if (log_level == SYSLOG_LEVEL_DEBUG1)
				log_level = SYSLOG_LEVEL_DEBUG2;
			else if (log_level == SYSLOG_LEVEL_DEBUG2)
				log_level = SYSLOG_LEVEL_DEBUG3;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'C':
			known_hostkey_file = optarg;
			break;
		case 'D':
			foreground = 1;
			dump_packets++;
			break;
		case 'L':
			if (parse_forward(&fwd, optarg, 0, 0) == 0)
				fatal("cannot parse: %s", optarg);
			if (fwd.listen_host == NULL)
				fwd.listen_host = "0.0.0.0";
			break;
		case 'S':
			hostkey_file = optarg;
			break;
		default:
			usage();
			break;
		}
	}
	log_init(__progname, log_level, log_facility, log_stderr);
	if (hostkey_file &&
	    (r = sshkey_load_private(hostkey_file, "", &hostkey, NULL)) != 0)
		fatal("sshkey_load_private: %s: %s", hostkey_file, ssh_err(r));
	if (known_hostkey_file &&
	    (r = sshkey_load_public(known_hostkey_file, &known_hostkey,
	    NULL)) != 0)
		fatal("sshkey_load_public: %s: %s", known_hostkey_file,
		    ssh_err(r));
	if (!foreground)
		daemon(0, 0);
	event_init();
	if ((fd = do_listen(fwd.listen_host, fwd.listen_port)) < 0)
		fatal(" do_listen failed");
	event_set(&ev, fd, EV_READ, accept_cb, &ev);
	event_add(&ev, NULL);
	event_dispatch();
	exit(1);
}
