/* $OpenBSD: auth2-pubkey.c,v 1.38 2013/06/21 00:34:49 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"
#include "sshbuf.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "pathnames.h"
#include "uidswap.h"
#include "auth-options.h"
#include "canohost.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "misc.h"
#include "authfile.h"
#include "match.h"
#include "err.h"

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern u_int session_id2_len;

static int
userauth_pubkey(struct ssh *ssh)
{
	struct authctxt *authctxt = ssh->authctxt;
	struct sshbuf *b;
	struct sshkey *key = NULL;
	char *pkalg, *userstyle = NULL;
	u_char *pkblob, *sig, have_sig;
	size_t blen, slen;
	int r, pktype;
	int authenticated = 0;

	if (!authctxt->valid) {
		debug2("%s: disabled because of invalid user", __func__);
		return 0;
	}
	if ((r = sshpkt_get_u8(ssh, &have_sig)) != 0)
		fatal("%s: sshpkt_get_u8 failed: %s", __func__, ssh_err(r));
	if (ssh->compat & SSH_BUG_PKAUTH) {
		debug2("%s: SSH_BUG_PKAUTH", __func__);
		if ((b = sshbuf_new()) == NULL)
			fatal("%s: sshbuf_new failed", __func__);
		/* no explicit pkalg given */
		/* so we have to extract the pkalg from the pkblob */
		if ((r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0 ||
		    (r = sshbuf_put(b, pkblob, blen)) != 0 ||
		    (r = sshbuf_get_cstring(b, &pkalg, NULL)) != 0)
			fatal("%s: failed: %s", __func__, ssh_err(r));
		sshbuf_free(b);
	} else {
		if ((r = sshpkt_get_cstring(ssh, &pkalg, NULL)) != 0 ||
		    (r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0)
			fatal("%s: sshpkt_get_cstring failed: %s",
			    __func__, ssh_err(r));
	}
	pktype = sshkey_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		logit("%s: unsupported public key algorithm: %s", __func__,
		    pkalg);
		goto done;
	}
	if ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
		error("%s: could not parse key: %s", __func__, ssh_err(r));
		goto done;
	}
	if (key == NULL) {
		error("%s: cannot decode key: %s", __func__, pkalg);
		goto done;
	}
	if (key->type != pktype) {
		error("%s: type mismatch for decoded key "
		    "(received %d, expected %d)", __func__, key->type, pktype);
		goto done;
	}
	if (have_sig) {
		if ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		if ((b = sshbuf_new()) == NULL)
			fatal("%s: sshbuf_new failed", __func__);
		if (ssh->compat & SSH_OLD_SESSIONID) {
			if ((r = sshbuf_put(b, session_id2,
			    session_id2_len)) != 0)
				fatal("%s: sshbuf_put session id: %s",
				    __func__, ssh_err(r));
		} else {
			if ((r = sshbuf_put_string(b, session_id2,
			    session_id2_len)) != 0)
				fatal("%s: sshbuf_put_string session id: %s",
				    __func__, ssh_err(r));
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, ssh->compat & SSH_BUG_PKSERVICE ?
		    "ssh-userauth" : authctxt->service)) != 0)
			fatal("%s: build packet failed: %s",
			    __func__, ssh_err(r));
		if (ssh->compat & SSH_BUG_PKAUTH) {
			if ((r = sshbuf_put_u8(b, have_sig)) != 0)
				fatal("%s: build packet failed: %s",
				    __func__, ssh_err(r));
		} else {
			if ((r = sshbuf_put_cstring(b, "publickey")) != 0 ||
			    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
			    (r = sshbuf_put_cstring(b, pkalg) != 0))
				fatal("%s: build packet failed: %s",
				    __func__, ssh_err(r));
		}
		if ((r = sshbuf_put_string(b, pkblob, blen)) != 0)
			fatal("%s: build packet failed: %s",
			    __func__, ssh_err(r));
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		pubkey_auth_info(authctxt, key, NULL);

		/* test for correct signature */
		authenticated = 0;
		if (PRIVSEP(user_key_allowed(authctxt->pw, key)) &&
		    PRIVSEP(sshkey_verify(key, sig, slen, sshbuf_ptr(b),
		    sshbuf_len(b), ssh->compat)) == 0)
			authenticated = 1;
		sshbuf_free(b);
		free(sig);
	} else {
		debug("test whether pkalg/pkblob are acceptable");
		if ((r = sshpkt_get_end(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		if (PRIVSEP(user_key_allowed(authctxt->pw, key))) {
			if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_string(ssh, pkblob, blen)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal("%s: %s", __func__, ssh_err(r));
			ssh_packet_write_wait(ssh);
			authctxt->postponed = 1;
		}
	}
	if (authenticated != 1)
		auth_clear_options();
done:
	debug2("%s: authenticated %d pkalg %s", __func__, authenticated, pkalg);
	if (key != NULL)
		sshkey_free(key);
	free(userstyle);
	free(pkalg);
	free(pkblob);
	return authenticated;
}

void
pubkey_auth_info(struct authctxt *authctxt, const struct sshkey *key,
    const char *fmt, ...)
{
	char *fp, *extra;
	va_list ap;
	int i;

	extra = NULL;
	if (fmt != NULL) {
		va_start(ap, fmt);
		i = vasprintf(&extra, fmt, ap);
		va_end(ap);
		if (i < 0 || extra == NULL)
			fatal("%s: vasprintf failed", __func__);
	}

	if (sshkey_is_cert(key)) {
		fp = sshkey_fingerprint(key->cert->signature_key,
		    SSH_FP_MD5, SSH_FP_HEX);
		auth_info(authctxt, "%s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(key), key->cert->key_id,
		    (unsigned long long)key->cert->serial,
		    sshkey_type(key->cert->signature_key), fp,
		    extra == NULL ? "" : ", ", extra == NULL ? "" : extra);
		free(fp);
	} else {
		fp = sshkey_fingerprint(key, SSH_FP_MD5, SSH_FP_HEX);
		auth_info(authctxt, "%s %s%s%s", sshkey_type(key), fp,
		    extra == NULL ? "" : ", ", extra == NULL ? "" : extra);
		free(fp);
	}
	free(extra);
}

static int
match_principals_option(const char *principal_list, struct sshkey_cert *cert)
{
	char *result;
	u_int i;

	/* XXX percent_expand() sequences for authorized_principals? */

	for (i = 0; i < cert->nprincipals; i++) {
		if ((result = match_list(cert->principals[i],
		    principal_list, NULL)) != NULL) {
			debug3("matched principal from key options \"%.100s\"",
			    result);
			free(result);
			return 1;
		}
	}
	return 0;
}

static int
match_principals_file(char *file, struct passwd *pw, struct sshkey_cert *cert)
{
	FILE *f;
	char line[SSH_MAX_PUBKEY_BYTES], *cp, *ep, *line_opts;
	u_long linenum = 0;
	u_int i;

	temporarily_use_uid(pw);
	debug("trying authorized principals file %s", file);
	if ((f = auth_openprincipals(file, pw, options.strict_modes)) == NULL) {
		restore_uid();
		return 0;
	}
	while (read_keyfile_line(f, file, line, sizeof(line), &linenum) != -1) {
		/* Skip leading whitespace. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		/* Skip blank and comment lines. */
		if ((ep = strchr(cp, '#')) != NULL)
			*ep = '\0';
		if (!*cp || *cp == '\n')
			continue;
		/* Trim trailing whitespace. */
		ep = cp + strlen(cp) - 1;
		while (ep > cp && (*ep == '\n' || *ep == ' ' || *ep == '\t'))
			*ep-- = '\0';
		/*
		 * If the line has internal whitespace then assume it has
		 * key options.
		 */
		line_opts = NULL;
		if ((ep = strrchr(cp, ' ')) != NULL ||
		    (ep = strrchr(cp, '\t')) != NULL) {
			for (; *ep == ' ' || *ep == '\t'; ep++)
				;
			line_opts = cp;
			cp = ep;
		}
		for (i = 0; i < cert->nprincipals; i++) {
			if (strcmp(cp, cert->principals[i]) == 0) {
				debug3("matched principal \"%.100s\" "
				    "from file \"%s\" on line %lu",
				    cert->principals[i], file, linenum);
				if (auth_parse_options(pw, line_opts,
				    file, linenum) != 1)
					continue;
				fclose(f);
				restore_uid();
				return 1;
			}
		}
	}
	fclose(f);
	restore_uid();
	return 0;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
static int
check_authkeys_file(FILE *f, char *file, struct sshkey *key, struct passwd *pw)
{
	char line[SSH_MAX_PUBKEY_BYTES];
	const char *reason;
	int found_key = 0;
	u_long linenum = 0;
	struct sshkey *found = NULL;
	char *fp;

	found_key = 0;
	found = NULL;
	while (read_keyfile_line(f, file, line, sizeof(line), &linenum) != -1) {
		char *cp, *key_options = NULL;
		if (found != NULL)
			sshkey_free(found);
		found = sshkey_new(sshkey_is_cert(key) ? KEY_UNSPEC : key->type);
		if (found == NULL)
			goto done;
		auth_clear_options();

		/* Skip leading whitespace, empty and comment lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;

		if (sshkey_read(found, &cp) != 0) {
			/* no key?  check if there are options for this key */
			int quoted = 0;
			debug2("user_key_allowed: check options: '%s'", cp);
			key_options = cp;
			for (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
				if (*cp == '\\' && cp[1] == '"')
					cp++;	/* Skip both */
				else if (*cp == '"')
					quoted = !quoted;
			}
			/* Skip remaining whitespace. */
			for (; *cp == ' ' || *cp == '\t'; cp++)
				;
			if (sshkey_read(found, &cp) != 0) {
				debug2("user_key_allowed: advance: '%s'", cp);
				/* still no key?  advance to next line*/
				continue;
			}
		}
		if (sshkey_is_cert(key)) {
			if (!sshkey_equal(found, key->cert->signature_key))
				continue;
			if (auth_parse_options(pw, key_options, file,
			    linenum) != 1)
				continue;
			if (!key_is_cert_authority)
				continue;
			fp = sshkey_fingerprint(found, SSH_FP_MD5,
			    SSH_FP_HEX);
			debug("matching CA found: file %s, line %lu, %s %s",
			    file, linenum, sshkey_type(found), fp);
			/*
			 * If the user has specified a list of principals as
			 * a key option, then prefer that list to matching
			 * their username in the certificate principals list.
			 */
			if (authorized_principals != NULL &&
			    !match_principals_option(authorized_principals,
			    key->cert)) {
				reason = "Certificate does not contain an "
				    "authorized principal";
 fail_reason:
				free(fp);
				error("%s", reason);
				auth_debug_add("%s", reason);
				continue;
			}
			if (sshkey_cert_check_authority(key, 0, 0,
			    authorized_principals == NULL ? pw->pw_name : NULL,
			    &reason) != 0)
				goto fail_reason;
			if (auth_cert_options(key, pw) != 0) {
				free(fp);
				continue;
			}
			verbose("Accepted certificate ID \"%s\" "
			    "signed by %s CA %s via %s", key->cert->key_id,
			    sshkey_type(found), fp, file);
			free(fp);
			found_key = 1;
			break;
		} else if (sshkey_equal(found, key)) {
			if (auth_parse_options(pw, key_options, file,
			    linenum) != 1)
				continue;
			if (key_is_cert_authority)
				continue;
			found_key = 1;
			fp = sshkey_fingerprint(found, SSH_FP_MD5, SSH_FP_HEX);
			debug("matching key found: file %s, line %lu %s %s",
			    file, linenum, sshkey_type(found), fp);
			free(fp);
			break;
		}
	}
 done:
	if (found != NULL)
		sshkey_free(found);
	if (!found_key)
		debug2("key not found");
	return found_key;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
static int
user_cert_trusted_ca(struct passwd *pw, struct sshkey *key)
{
	char *ca_fp, *principals_file = NULL;
	const char *reason;
	int r, ret = 0;

	if (!sshkey_is_cert(key) || options.trusted_user_ca_keys == NULL)
		return 0;

	ca_fp = sshkey_fingerprint(key->cert->signature_key,
	    SSH_FP_MD5, SSH_FP_HEX);

	switch ((r = sshkey_in_file(key->cert->signature_key,
	    options.trusted_user_ca_keys, 1))) {
	case 0:
		break;
	case SSH_ERR_KEY_NOT_FOUND:
		debug2("%s: CA %s %s is not listed in %s", __func__,
		    sshkey_type(key->cert->signature_key), ca_fp,
		    options.trusted_user_ca_keys);
		goto out;
	default:
		error("%s: error checking TrustedUserCAKeys file \"%s\": %s",
		    __func__, options.trusted_user_ca_keys, ssh_err(r));
		goto out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	if ((principals_file = authorized_principals_file(pw)) != NULL) {
		if (!match_principals_file(principals_file, pw, key->cert)) {
			reason = "Certificate does not contain an "
			    "authorized principal";
 fail_reason:
			error("%s", reason);
			auth_debug_add("%s", reason);
			goto out;
		}
	}
	if (sshkey_cert_check_authority(key, 0, 1,
	    principals_file == NULL ? pw->pw_name : NULL, &reason) != 0)
		goto fail_reason;
	if (auth_cert_options(key, pw) != 0)
		goto out;

	verbose("Accepted certificate ID \"%s\" signed by %s CA %s via %s",
	    key->cert->key_id, sshkey_type(key->cert->signature_key), ca_fp,
	    options.trusted_user_ca_keys);
	ret = 1;

 out:
	free(principals_file);
	free(ca_fp);
	return ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
static int
user_key_allowed2(struct passwd *pw, struct sshkey *key, char *file)
{
	FILE *f;
	int found_key = 0;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	if ((f = auth_openkeyfile(file, pw, options.strict_modes)) != NULL) {
		found_key = check_authkeys_file(f, file, key, pw);
		fclose(f);
	}

	restore_uid();
	return found_key;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
static int
user_key_command_allowed2(struct passwd *user_pw, struct sshkey *key)
{
	FILE *f;
	int ok, found_key = 0;
	struct passwd *pw;
	struct stat st;
	int status, devnull, p[2], i;
	pid_t pid;
	char *username, errmsg[512];

	if (options.authorized_keys_command == NULL ||
	    options.authorized_keys_command[0] != '/')
		return 0;

	if (options.authorized_keys_command_user == NULL) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		return 0;
	}

	username = percent_expand(options.authorized_keys_command_user,
	    "u", user_pw->pw_name, (char *)NULL);
	pw = getpwnam(username);
	if (pw == NULL) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		free(username);
		return 0;
	}
	free(username);

	temporarily_use_uid(pw);

	if (stat(options.authorized_keys_command, &st) < 0) {
		error("Could not stat AuthorizedKeysCommand \"%s\": %s",
		    options.authorized_keys_command, strerror(errno));
		goto out;
	}
	if (auth_secure_path(options.authorized_keys_command, &st, NULL, 0,
	    errmsg, sizeof(errmsg)) != 0) {
		error("Unsafe AuthorizedKeysCommand: %s", errmsg);
		goto out;
	}

	if (pipe(p) != 0) {
		error("%s: pipe: %s", __func__, strerror(errno));
		goto out;
	}

	debug3("Running AuthorizedKeysCommand: \"%s %s\" as \"%s\"",
	    options.authorized_keys_command, user_pw->pw_name, pw->pw_name);

	/*
	 * Don't want to call this in the child, where it can fatal() and
	 * run cleanup_exit() code.
	 */
	restore_uid();

	switch ((pid = fork())) {
	case -1: /* error */
		error("%s: fork: %s", __func__, strerror(errno));
		close(p[0]);
		close(p[1]);
		return 0;
	case 0: /* child */
		for (i = 0; i < NSIG; i++)
			signal(i, SIG_DFL);

		if ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", __func__, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		/* Keep stderr around a while longer to catch errors */
		if (dup2(devnull, STDIN_FILENO) == -1 ||
		    dup2(p[1], STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", __func__, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		/* Don't use permanently_set_uid() here to avoid fatal() */
		if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0) {
			error("setresgid %u: %s", (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0) {
			error("setresuid %u: %s", (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		if (dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", __func__, strerror(errno));
			_exit(1);
		}

		execl(options.authorized_keys_command,
		    options.authorized_keys_command, user_pw->pw_name, NULL);

		error("AuthorizedKeysCommand %s exec failed: %s",
		    options.authorized_keys_command, strerror(errno));
		_exit(127);
	default: /* parent */
		break;
	}

	temporarily_use_uid(pw);

	close(p[1]);
	if ((f = fdopen(p[0], "r")) == NULL) {
		error("%s: fdopen: %s", __func__, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
			;
		goto out;
	}
	ok = check_authkeys_file(f, options.authorized_keys_command, key, pw);
	fclose(f);

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR) {
			error("%s: waitpid: %s", __func__, strerror(errno));
			goto out;
		}
	}
	if (WIFSIGNALED(status)) {
		error("AuthorizedKeysCommand %s exited on signal %d",
		    options.authorized_keys_command, WTERMSIG(status));
		goto out;
	} else if (WEXITSTATUS(status) != 0) {
		error("AuthorizedKeysCommand %s returned status %d",
		    options.authorized_keys_command, WEXITSTATUS(status));
		goto out;
	}
	found_key = ok;
 out:
	restore_uid();
	return found_key;
}

/*
 * Check whether key authenticates and authorises the user.
 */
int
user_key_allowed(struct passwd *pw, struct sshkey *key)
{
	u_int success, i;
	char *file;

	if (auth_key_is_revoked(key))
		return 0;
	if (sshkey_is_cert(key) &&
	    auth_key_is_revoked(key->cert->signature_key))
		return 0;

	success = user_cert_trusted_ca(pw, key);
	if (success)
		return success;

	success = user_key_command_allowed2(pw, key);
	if (success > 0)
		return success;

	for (i = 0; !success && i < options.num_authkeys_files; i++) {

		if (strcasecmp(options.authorized_keys_files[i], "none") == 0)
			continue;
		file = expand_authorized_keys(
		    options.authorized_keys_files[i], pw);

		success = user_key_allowed2(pw, key, file);
		free(file);
	}

	return success;
}

struct authmethod method_pubkey = {
	"publickey",
	userauth_pubkey,
	&options.pubkey_authentication
};
