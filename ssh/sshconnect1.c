/* $OpenBSD: sshconnect1.c,v 1.71 2013/05/17 00:13:14 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code to connect to a remote host, and to perform the client side of the
 * login (authentication) dialog.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/bn.h>
#include <openssl/md5.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh1.h"
#include "rsa.h"
#include "packet.h"
#include "key.h"
#include "cipher.h"
#include "kex.h"
#include "uidswap.h"
#include "log.h"
#include "readconf.h"
#include "authfd.h"
#include "sshconnect.h"
#include "authfile.h"
#include "misc.h"
#include "canohost.h"
#include "hostfile.h"
#include "auth.h"
#include "err.h"

/* Session id for the current session. */
u_char session_id[16];
u_int supported_authentications = 0;

extern Options options;
extern char *__progname;

/*
 * Checks if the user has an authentication agent, and if so, tries to
 * authenticate using the agent.
 */
static int
try_agent_authentication(struct ssh *ssh)
{
	int r, type, agent_fd, ret = 0;
	u_char response[16];
	size_t i;
	BIGNUM *challenge;
	struct ssh_identitylist *idlist = NULL;

	/* Get connection to the agent. */
	if ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		if (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug("%s: ssh_get_authentication_socket: %s",
			    __func__, ssh_err(r));
		return 0;
	}

	if ((challenge = BN_new()) == NULL)
		fatal("try_agent_authentication: BN_new failed");

	/* Loop through identities served by the agent. */
	if ((r = ssh_fetch_identitylist(agent_fd, 1, &idlist)) != 0) {
		if (r != SSH_ERR_AGENT_NO_IDENTITIES)
			debug("%s: ssh_fetch_identitylist: %s",
			    __func__, ssh_err(r));
		goto out;
	}
	for (i = 0; i < idlist->nkeys; i++) {
		/* Try this identity. */
		debug("Trying RSA authentication via agent with '%.100s'",
		    idlist->comments[i]);

		/*
		 * Tell the server that we are willing to authenticate
		 * using this key.
		 */
		if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_RSA)) != 0 ||
		    (r = sshpkt_put_bignum1(ssh, idlist->keys[i]->rsa->n)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		ssh_packet_write_wait(ssh);

		/* Wait for server's response. */
		type = ssh_packet_read(ssh);

		/* The server sends failure if it doesn't like our key or
		   does not support RSA authentication. */
		if (type == SSH_SMSG_FAILURE) {
			debug("Server refused our key.");
			continue;
		}
		/* Otherwise it should have sent a challenge. */
		if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
			ssh_packet_disconnect(ssh, "Protocol error during RSA "
			    "authentication: %d", type);

		if ((r = sshpkt_get_bignum1(ssh, challenge)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));

		debug("Received RSA challenge from server.");

		/* Ask the agent to decrypt the challenge. */
		if ((r = ssh_decrypt_challenge(agent_fd, idlist->keys[i],
		    challenge, session_id, response)) != 0) {
			/*
			 * The agent failed to authenticate this identifier
			 * although it advertised it supports this.  Just
			 * return a wrong value.
			 */
			logit("Authentication agent failed to decrypt "
			    "challenge: %s", ssh_err(r));
			memset(response, 0, sizeof(response));
		}
		debug("Sending response to RSA challenge.");

		/* Send the decrypted challenge back to the server. */
		if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_RSA_RESPONSE)) != 0 ||
		    (r = sshpkt_put(ssh, &response, sizeof(response))) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		ssh_packet_write_wait(ssh);

		/* Wait for response from the server. */
		type = ssh_packet_read(ssh);

		/*
		 * The server returns success if it accepted the
		 * authentication.
		 */
		if (type == SSH_SMSG_SUCCESS) {
			debug("RSA authentication accepted by server.");
			ret = 1;
			break;
		} else if (type != SSH_SMSG_FAILURE)
			ssh_packet_disconnect(ssh, "Protocol error waiting RSA auth "
			    "response: %d", type);
	}
	if (ret != 1)
		debug("RSA authentication using agent refused.");
 out:
	ssh_free_identitylist(idlist);
	ssh_close_authentication_socket(agent_fd);
	BN_clear_free(challenge);
	return ret;
}

/*
 * Computes the proper response to a RSA challenge, and sends the response to
 * the server.
 */
static void
respond_to_rsa_challenge(struct ssh *ssh, BIGNUM * challenge, RSA * prv)
{
	u_char buf[32], response[16];
	MD5_CTX md;
	int r, len;

	/* Decrypt the challenge using the private key. */
	/* XXX think about Bleichenbacher, too */
	if ((r = rsa_private_decrypt(challenge, challenge, prv)) != 0) {
		ssh_packet_disconnect(ssh,  "%s: rsa_private_decrypt: %s",
		    __func__, ssh_err(r));
	}

	/* Compute the response. */
	/* The response is MD5 of decrypted challenge plus session id. */
	len = BN_num_bytes(challenge);
	if (len <= 0 || (u_int)len > sizeof(buf))
		ssh_packet_disconnect(ssh,
		    "respond_to_rsa_challenge: bad challenge length %d", len);

	memset(buf, 0, sizeof(buf));
	BN_bn2bin(challenge, buf + sizeof(buf) - len);
	MD5_Init(&md);
	MD5_Update(&md, buf, 32);
	MD5_Update(&md, session_id, 16);
	MD5_Final(response, &md);

	debug("Sending response to host key RSA challenge.");

	/* Send the response back to the server. */
	if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_RSA_RESPONSE)) != 0 ||
	    (r = sshpkt_put(ssh, &response, sizeof(response))) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	ssh_packet_write_wait(ssh);

	memset(buf, 0, sizeof(buf));
	memset(response, 0, sizeof(response));
	memset(&md, 0, sizeof(md));
}

/*
 * Checks if the user has authentication file, and if so, tries to authenticate
 * the user using it.
 */
static int
try_rsa_authentication(struct ssh *ssh, int idx)
{
	BIGNUM *challenge;
	struct sshkey *public, *private;
	char buf[300], *passphrase, *comment, *authfile;
	int r, i, perm_ok = 1, type, quit;

	public = options.identity_keys[idx];
	authfile = options.identity_files[idx];
	comment = xstrdup(authfile);

	debug("Trying RSA authentication with key '%.100s'", comment);

	/* Tell the server that we are willing to authenticate using this key. */
	if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_RSA)) != 0 ||
	    (r = sshpkt_put_bignum1(ssh, public->rsa->n)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	ssh_packet_write_wait(ssh);

	/* Wait for server's response. */
	type = ssh_packet_read(ssh);

	/*
	 * The server responds with failure if it doesn't like our key or
	 * doesn't support RSA authentication.
	 */
	if (type == SSH_SMSG_FAILURE) {
		debug("Server refused our key.");
		free(comment);
		return 0;
	}
	/* Otherwise, the server should respond with a challenge. */
	if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
		ssh_packet_disconnect(ssh,
		    "Protocol error during RSA authentication: %d", type);

	/* Get the challenge from the packet. */
	if ((challenge = BN_new()) == NULL)
		fatal("try_rsa_authentication: BN_new failed");
	if ((r = sshpkt_get_bignum1(ssh, challenge)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)

	debug("Received RSA challenge from server.");

	/*
	 * If the key is not stored in external hardware, we have to
	 * load the private key.  Try first with empty passphrase; if it
	 * fails, ask for a passphrase.
	 */
	if (public->flags & SSHKEY_FLAG_EXT) {
		private = public;
		r = 0;
	} else {
		r = sshkey_load_private_type(KEY_RSA1, authfile, "", &private,
		    NULL, &perm_ok);
	}
	switch (r) {
	case 0:
		break;
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		if (options.batch_mode)
			error("Key file \"%s\" requires passphrase", authfile);
		break;
	case SSH_ERR_SYSTEM_ERROR:
		if (errno == ENOENT) {
			debug2("Key file \"%s\" does not exist", authfile);
			break;
		}
		/* FALLTHROUGH */
	default:
		error("Load RSA1 key \"%s\": %s", authfile, ssh_err(r));
	}
	if (r == SSH_ERR_KEY_WRONG_PASSPHRASE &&
	    !options.batch_mode && perm_ok) {
		snprintf(buf, sizeof(buf),
		    "Enter passphrase for RSA key '%.100s': ", comment);
		for (i = 0; i < options.number_of_password_prompts; i++) {
			passphrase = read_passphrase(buf, 0);
			r = 0;
			if (strcmp(passphrase, "") != 0) {
				switch ((r = sshkey_load_private_type(KEY_RSA1,
				    authfile, passphrase, &private,
				    NULL, NULL))) {
				case SSH_ERR_KEY_WRONG_PASSPHRASE:
				case 0:
					quit = 0;
					break;
				default:
					error("Load RSA1 key \"%s\": %s",
					    authfile, ssh_err(r));
					quit = 1;
					break;
				}
			} else {
				debug2("no passphrase given, try next key");
				quit = 1;
			}
			memset(passphrase, 0, strlen(passphrase));
			free(passphrase);
			if (private != NULL || quit)
				break;
			debug2("bad passphrase given, try again...");
		}
	}
	/* We no longer need the comment. */
	free(comment);

	if (private == NULL) {
		if (!options.batch_mode && perm_ok)
			error("Bad passphrase."); /* XXX check r */

		/* Send a dummy response packet to avoid protocol error. */
		memset(buf, 0, 16);
		if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_RSA_RESPONSE)) != 0 ||
		    (r = sshpkt_put(ssh, buf, 16)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		ssh_packet_write_wait(ssh);

		/* Expect the server to reject it... */
		ssh_packet_read_expect(ssh, SSH_SMSG_FAILURE);
		BN_clear_free(challenge);
		return 0;
	}

	/* Compute and send a response to the challenge. */
	respond_to_rsa_challenge(ssh, challenge, private->rsa);

	/* Destroy the private key unless it in external hardware. */
	if (!(private->flags & SSHKEY_FLAG_EXT))
		sshkey_free(private);

	/* We no longer need the challenge. */
	BN_clear_free(challenge);

	/* Wait for response from the server. */
	type = ssh_packet_read(ssh);
	if (type == SSH_SMSG_SUCCESS) {
		debug("RSA authentication accepted by server.");
		return 1;
	}
	if (type != SSH_SMSG_FAILURE)
		ssh_packet_disconnect(ssh,
		    "Protocol error waiting RSA auth response: %d", type);
	debug("RSA authentication refused.");
	return 0;
}

/*
 * Tries to authenticate the user using combined rhosts or /etc/hosts.equiv
 * authentication and RSA host authentication.
 */
static int
try_rhosts_rsa_authentication(struct ssh *ssh, const char *local_user,
    struct sshkey *host_key)
{
	int r, type;
	BIGNUM *challenge;

	debug("Trying rhosts or /etc/hosts.equiv with RSA host authentication.");

	/* Tell the server that we are willing to authenticate using this key. */
	if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_RHOSTS_RSA)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, local_user)) != 0 ||
	    (r = sshpkt_put_u32(ssh, BN_num_bits(host_key->rsa->n))) != 0 ||
	    (r = sshpkt_put_bignum1(ssh, host_key->rsa->e)) != 0 ||
	    (r = sshpkt_put_bignum1(ssh, host_key->rsa->n)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	ssh_packet_write_wait(ssh);

	/* Wait for server's response. */
	type = ssh_packet_read(ssh);

	/* The server responds with failure if it doesn't admit our
	   .rhosts authentication or doesn't know our host key. */
	if (type == SSH_SMSG_FAILURE) {
		debug("Server refused our rhosts authentication or host key.");
		return 0;
	}
	/* Otherwise, the server should respond with a challenge. */
	if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
		ssh_packet_disconnect(ssh, "Protocol error during RSA authentication: %d", type);

	/* Get the challenge from the packet. */
	if ((challenge = BN_new()) == NULL)
		fatal("try_rhosts_rsa_authentication: BN_new failed");
	if ((r = sshpkt_get_bignum1(ssh, challenge)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	debug("Received RSA challenge for host key from server.");

	/* Compute a response to the challenge. */
	respond_to_rsa_challenge(ssh, challenge, host_key->rsa);

	/* We no longer need the challenge. */
	BN_clear_free(challenge);

	/* Wait for response from the server. */
	type = ssh_packet_read(ssh);
	if (type == SSH_SMSG_SUCCESS) {
		debug("Rhosts or /etc/hosts.equiv with RSA host authentication accepted by server.");
		return 1;
	}
	if (type != SSH_SMSG_FAILURE)
		ssh_packet_disconnect(ssh,
		    "Protocol error waiting RSA auth response: %d", type);
	debug("Rhosts or /etc/hosts.equiv with RSA host authentication refused.");
	return 0;
}

/*
 * Tries to authenticate with any string-based challenge/response system.
 * Note that the client code is not tied to s/key or TIS.
 */
static int
try_challenge_response_authentication(struct ssh *ssh)
{
	int type, r, i;
	char prompt[1024];
	char *challenge, *response;

	debug("Doing challenge response authentication.");

	for (i = 0; i < options.number_of_password_prompts; i++) {
		/* request a challenge */
		if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_TIS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		ssh_packet_write_wait(ssh);

		type = ssh_packet_read(ssh);
		if (type != SSH_SMSG_FAILURE &&
		    type != SSH_SMSG_AUTH_TIS_CHALLENGE) {
			ssh_packet_disconnect(ssh, "Protocol error: got %d in response "
			    "to SSH_CMSG_AUTH_TIS", type);
		}
		if (type != SSH_SMSG_AUTH_TIS_CHALLENGE) {
			debug("No challenge.");
			return 0;
		}
		if ((r = sshpkt_get_cstring(ssh, &challenge, NULL)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		snprintf(prompt, sizeof prompt, "%s%s", challenge,
		    strchr(challenge, '\n') ? "" : "\nResponse: ");
		free(challenge);
		if (i != 0)
			error("Permission denied, please try again.");
		if (options.cipher == SSH_CIPHER_NONE)
			logit("WARNING: Encryption is disabled! "
			    "Response will be transmitted in clear text.");
		response = read_passphrase(prompt, 0);
		if (strcmp(response, "") == 0) {
			free(response);
			break;
		}
		if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_TIS_RESPONSE)) != 0 ||
		    (r = ssh_put_password(ssh, response)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		memset(response, 0, strlen(response));
		free(response);
		ssh_packet_write_wait(ssh);
		type = ssh_packet_read(ssh);
		if (type == SSH_SMSG_SUCCESS)
			return 1;
		if (type != SSH_SMSG_FAILURE)
			ssh_packet_disconnect(ssh,
			    "Protocol error: got %d in response "
			    "to SSH_CMSG_AUTH_TIS_RESPONSE", type);
	}
	/* failure */
	return 0;
}

/*
 * Tries to authenticate with plain passwd authentication.
 */
static int
try_password_authentication(struct ssh *ssh, char *prompt)
{
	int type, i, r;
	char *password;

	debug("Doing password authentication.");
	if (options.cipher == SSH_CIPHER_NONE)
		logit("WARNING: Encryption is disabled! Password will be transmitted in clear text.");
	for (i = 0; i < options.number_of_password_prompts; i++) {
		if (i != 0)
			error("Permission denied, please try again.");
		password = read_passphrase(prompt, 0);
		if ((r = sshpkt_start(ssh, SSH_CMSG_AUTH_PASSWORD)) != 0 ||
		    (r = ssh_put_password(ssh, password)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal("%s: %s", __func__, ssh_err(r));
		memset(password, 0, strlen(password));
		free(password);
		ssh_packet_write_wait(ssh);

		type = ssh_packet_read(ssh);
		if (type == SSH_SMSG_SUCCESS)
			return 1;
		if (type != SSH_SMSG_FAILURE)
			ssh_packet_disconnect(ssh,
			    "Protocol error: got %d in response to passwd auth", type);
	}
	/* failure */
	return 0;
}

/*
 * SSH1 key exchange
 */
void
ssh_kex(struct ssh *ssh, char *host, struct sockaddr *hostaddr)
{
	int i, r;
	BIGNUM *key;
	struct sshkey *host_key, *server_key;
	int rbits;
	int ssh_cipher_default = SSH_CIPHER_3DES;
	u_char session_key[SSH_SESSION_KEY_LENGTH];
	u_char cookie[8];
	u_int bits, supported_ciphers;
	u_int server_flags, client_flags;

	debug("Waiting for server public key.");

	/* Wait for a public key packet from the server. */
	ssh_packet_read_expect(ssh, SSH_SMSG_PUBLIC_KEY);

	/* Get cookie from the packet. */
	if ((r = sshpkt_get(ssh, &cookie, 8)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	/* Get the public key. */
	if ((server_key = sshkey_new(KEY_RSA1)) == NULL)
		fatal("%s: sshkey_new failed", __func__);
	if ((r = sshpkt_get_u32(ssh, &bits)) != 0 ||
	    (r = sshpkt_get_bignum1(ssh, server_key->rsa->e)) != 0 ||
	    (r = sshpkt_get_bignum1(ssh, server_key->rsa->n)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	rbits = BN_num_bits(server_key->rsa->n);
	if (rbits < 0 || bits != (u_int)rbits) {
		logit("Warning: Server lies about size of server public key: "
		    "actual size is %d bits vs. announced %u.", rbits, bits);
		logit("Warning: This may be due to an old implementation of ssh.");
	}
	/* Get the host key. */
	if ((host_key = sshkey_new(KEY_RSA1)) == NULL)
		fatal("%s: sshkey_new failed", __func__);
	if ((r = sshpkt_get_u32(ssh, &bits)) != 0 ||
	    (r = sshpkt_get_bignum1(ssh, host_key->rsa->e)) != 0 ||
	    (r = sshpkt_get_bignum1(ssh, host_key->rsa->n)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	rbits = BN_num_bits(host_key->rsa->n);
	if (rbits < 0 || bits != (u_int)rbits) {
		logit("Warning: Server lies about size of server host key: "
		    "actual size is %d bits vs. announced %u.", rbits, bits);
		logit("Warning: This may be due to an old implementation of ssh.");
	}

	/* Get protocol flags. */
	if ((r = sshpkt_get_u32(ssh, &server_flags)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &supported_ciphers)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &supported_authentications)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	ssh_packet_set_protocol_flags(ssh, server_flags);

	debug("Received server public key (%d bits) and host key (%d bits).",
	    BN_num_bits(server_key->rsa->n), BN_num_bits(host_key->rsa->n));

	if (verify_host_key(host, hostaddr, host_key) == -1)
		fatal("Host key verification failed.");

	client_flags = SSH_PROTOFLAG_SCREEN_NUMBER | SSH_PROTOFLAG_HOST_IN_FWD_OPEN;

	if ((r = derive_ssh1_session_id(host_key->rsa->n, server_key->rsa->n,
	    cookie, session_id)) != 0)
		fatal("derive_ssh1_session_id: %s", ssh_err(r));

	/*
	 * Generate an encryption key for the session.   The key is a 256 bit
	 * random number, interpreted as a 32-byte key, with the least
	 * significant 8 bits being the first byte of the key.
	 */
	arc4random_stir();
	arc4random_buf(session_key, SSH_SESSION_KEY_LENGTH);

	/*
	 * According to the protocol spec, the first byte of the session key
	 * is the highest byte of the integer.  The session key is xored with
	 * the first 16 bytes of the session id.
	 */
	if ((key = BN_new()) == NULL)
		fatal("ssh_kex: BN_new failed");
	if (BN_set_word(key, 0) == 0)
		fatal("ssh_kex: BN_set_word failed");
	for (i = 0; i < SSH_SESSION_KEY_LENGTH; i++) {
		if (BN_lshift(key, key, 8) == 0)
			fatal("ssh_kex: BN_lshift failed");
		if (i < 16) {
			if (BN_add_word(key, session_key[i] ^ session_id[i])
			    == 0)
				fatal("ssh_kex: BN_add_word failed");
		} else {
			if (BN_add_word(key, session_key[i]) == 0)
				fatal("ssh_kex: BN_add_word failed");
		}
	}

	/*
	 * Encrypt the integer using the public key and host key of the
	 * server (key with smaller modulus first).
	 */
	if (BN_cmp(server_key->rsa->n, host_key->rsa->n) < 0) {
		/* Public key has smaller modulus. */
		if (BN_num_bits(host_key->rsa->n) <
		    BN_num_bits(server_key->rsa->n) + SSH_KEY_BITS_RESERVED) {
			fatal("respond_to_rsa_challenge: host_key %d < server_key %d + "
			    "SSH_KEY_BITS_RESERVED %d",
			    BN_num_bits(host_key->rsa->n),
			    BN_num_bits(server_key->rsa->n),
			    SSH_KEY_BITS_RESERVED);
		}
		if ((r = rsa_public_encrypt(key, key, server_key->rsa)) != 0 ||
		    (r = rsa_public_encrypt(key, key, host_key->rsa)) != 0)
			fatal("%s: rsa_public_encrypt: %s", __func__,
			    ssh_err(r));
	} else {
		/* Host key has smaller modulus (or they are equal). */
		if (BN_num_bits(server_key->rsa->n) <
		    BN_num_bits(host_key->rsa->n) + SSH_KEY_BITS_RESERVED) {
			fatal("respond_to_rsa_challenge: server_key %d < host_key %d + "
			    "SSH_KEY_BITS_RESERVED %d",
			    BN_num_bits(server_key->rsa->n),
			    BN_num_bits(host_key->rsa->n),
			    SSH_KEY_BITS_RESERVED);
		}
		if ((r = rsa_public_encrypt(key, key, host_key->rsa)) != 0 ||
		    (r = rsa_public_encrypt(key, key, server_key->rsa)) != 0)
			fatal("%s: rsa_public_encrypt: %s", __func__,
			    ssh_err(r));
	}

	/* Destroy the public keys since we no longer need them. */
	sshkey_free(server_key);
	sshkey_free(host_key);

	if (options.cipher == SSH_CIPHER_NOT_SET) {
		if (cipher_mask_ssh1(1) & supported_ciphers & (1 << ssh_cipher_default))
			options.cipher = ssh_cipher_default;
	} else if (options.cipher == SSH_CIPHER_INVALID ||
	    !(cipher_mask_ssh1(1) & (1 << options.cipher))) {
		logit("No valid SSH1 cipher, using %.100s instead.",
		    cipher_name(ssh_cipher_default));
		options.cipher = ssh_cipher_default;
	}
	/* Check that the selected cipher is supported. */
	if (!(supported_ciphers & (1 << options.cipher)))
		fatal("Selected cipher type %.100s not supported by server.",
		    cipher_name(options.cipher));

	debug("Encryption type: %.100s", cipher_name(options.cipher));

	/* Send the encrypted session key to the server. */
	if ((r = sshpkt_start(ssh, SSH_CMSG_SESSION_KEY)) != 0 ||
	    (r = sshpkt_put_u8(ssh, options.cipher)) != 0 ||
	    (r = sshpkt_put(ssh, cookie, 8)) != 0 ||
	    (r = sshpkt_put_bignum1(ssh, key)) != 0 ||
	    (r = sshpkt_put_u32(ssh, client_flags)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));

	BN_clear_free(key);
	ssh_packet_write_wait(ssh);

	debug("Sent encrypted session key.");

	/* Set the encryption key. */
	ssh_packet_set_encryption_key(ssh, session_key, SSH_SESSION_KEY_LENGTH,
	    options.cipher);

	/* We will no longer need the session key here.  Destroy any extra copies. */
	memset(session_key, 0, sizeof(session_key));

	/*
	 * Expect a success message from the server.  Note that this message
	 * will be received in encrypted form.
	 */
	ssh_packet_read_expect(ssh, SSH_SMSG_SUCCESS);

	debug("Received encrypted confirmation.");
}

/*
 * Authenticate user
 */
void
ssh_userauth1(struct ssh *ssh, const char *local_user, const char *server_user,
    char *host, Sensitive *sensitive)
{
	int r, i, type;

	if (supported_authentications == 0)
		fatal("ssh_userauth1: server supports no auth methods");

	/* Send the name of the user to log in as on the server. */
	if ((r = sshpkt_start(ssh, SSH_CMSG_USER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, server_user)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	ssh_packet_write_wait(ssh);

	/*
	 * The server should respond with success if no authentication is
	 * needed (the user has no password).  Otherwise the server responds
	 * with failure.
	 */
	type = ssh_packet_read(ssh);

	/* check whether the connection was accepted without authentication. */
	if (type == SSH_SMSG_SUCCESS)
		goto success;
	if (type != SSH_SMSG_FAILURE)
		ssh_packet_disconnect(ssh,
		    "Protocol error: got %d in response to SSH_CMSG_USER", type);

	/*
	 * Try .rhosts or /etc/hosts.equiv authentication with RSA host
	 * authentication.
	 */
	if ((supported_authentications & (1 << SSH_AUTH_RHOSTS_RSA)) &&
	    options.rhosts_rsa_authentication) {
		for (i = 0; i < sensitive->nkeys; i++) {
			if (sensitive->keys[i] != NULL &&
			    sensitive->keys[i]->type == KEY_RSA1 &&
			    try_rhosts_rsa_authentication(ssh, local_user,
			    sensitive->keys[i]))
				goto success;
		}
	}
	/* Try RSA authentication if the server supports it. */
	if ((supported_authentications & (1 << SSH_AUTH_RSA)) &&
	    options.rsa_authentication) {
		/*
		 * Try RSA authentication using the authentication agent. The
		 * agent is tried first because no passphrase is needed for
		 * it, whereas identity files may require passphrases.
		 */
		if (try_agent_authentication(ssh))
			goto success;

		/* Try RSA authentication for each identity. */
		for (i = 0; i < options.num_identity_files; i++)
			if (options.identity_keys[i] != NULL &&
			    options.identity_keys[i]->type == KEY_RSA1 &&
			    try_rsa_authentication(ssh, i))
				goto success;
	}
	/* Try challenge response authentication if the server supports it. */
	if ((supported_authentications & (1 << SSH_AUTH_TIS)) &&
	    options.challenge_response_authentication && !options.batch_mode) {
		if (try_challenge_response_authentication(ssh))
			goto success;
	}
	/* Try password authentication if the server supports it. */
	if ((supported_authentications & (1 << SSH_AUTH_PASSWORD)) &&
	    options.password_authentication && !options.batch_mode) {
		char prompt[80];

		snprintf(prompt, sizeof(prompt), "%.30s@%.128s's password: ",
		    server_user, host);
		if (try_password_authentication(ssh, prompt))
			goto success;
	}
	/* All authentication methods have failed.  Exit with an error message. */
	fatal("Permission denied.");
	/* NOTREACHED */

 success:
	return;	/* need statement after label */
}
