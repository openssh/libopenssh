/* $OpenBSD: authfile.c,v 1.97 2013/05/17 00:13:13 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains functions for reading and writing identity files, and
 * for reading the passphrase from the user.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
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
#include <sys/param.h>
#include <sys/uio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cipher.h"
#include "key.h"
#include "ssh.h"
#include "log.h"
#include "authfile.h"
#include "rsa.h"
#include "misc.h"
#include "atomicio.h"
#include "sshbuf.h"
#include "err.h"

#define MAX_KEY_FILE_SIZE	(1024 * 1024)

/* Version identification string for SSH v1 identity files. */
static const char authfile_id_string[] =
    "SSH PRIVATE KEY FILE FORMAT 1.1\n";

/*
 * Serialises the authentication (private) key to a blob, encrypting it with
 * passphrase.  The identification of the blob (lowest 64 bits of n) will
 * precede the key to provide identification of the key without needing a
 * passphrase.
 */
static int
sshkey_private_rsa1_to_blob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment)
{
	struct sshbuf *buffer = NULL, *encrypted = NULL;
	u_char buf[8];
	int r, cipher_num;
	struct sshcipher_ctx ciphercontext;
	const struct sshcipher *cipher;
	u_char *cp;

	/*
	 * If the passphrase is empty, use SSH_CIPHER_NONE to ease converting
	 * to another cipher; otherwise use SSH_AUTHFILE_CIPHER.
	 */
	cipher_num = (strcmp(passphrase, "") == 0) ?
	    SSH_CIPHER_NONE : SSH_AUTHFILE_CIPHER;
	if ((cipher = cipher_by_number(cipher_num)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	/* This buffer is used to build the secret part of the private key. */
	if ((buffer = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* Put checkbytes for checking passphrase validity. */
	if ((r = sshbuf_reserve(buffer, 4, &cp)) != 0)
		goto out;
	arc4random_buf(cp, 2);
	memcpy(cp + 2, cp, 2);

	/*
	 * Store the private key (n and e will not be stored because they
	 * will be stored in plain text, and storing them also in encrypted
	 * format would just give known plaintext).
	 * Note: q and p are stored in reverse order to SSL.
	 */
	if ((r = sshbuf_put_bignum1(buffer, key->rsa->d)) != 0 ||
	    (r = sshbuf_put_bignum1(buffer, key->rsa->iqmp)) != 0 ||
	    (r = sshbuf_put_bignum1(buffer, key->rsa->q)) != 0 ||
	    (r = sshbuf_put_bignum1(buffer, key->rsa->p)) != 0)
		goto out;

	/* Pad the part to be encrypted to a size that is a multiple of 8. */
	bzero(buf, 8);
	if ((r = sshbuf_put(buffer, buf, 8 - (sshbuf_len(buffer) % 8))) != 0)
		goto out;

	/* This buffer will be used to contain the data in the file. */
	if ((encrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* First store keyfile id string. */
	if ((r = sshbuf_put(encrypted, authfile_id_string,
	    sizeof(authfile_id_string))) != 0)
		goto out;

	/* Store cipher type and "reserved" field. */
	if ((r = sshbuf_put_u8(encrypted, cipher_num)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, 0)) != 0)
		goto out;

	/* Store public key.  This will be in plain text. */
	if ((r = sshbuf_put_u32(encrypted, BN_num_bits(key->rsa->n))) != 0 ||
	    (r = sshbuf_put_bignum1(encrypted, key->rsa->n) != 0) ||
	    (r = sshbuf_put_bignum1(encrypted, key->rsa->e) != 0) ||
	    (r = sshbuf_put_cstring(encrypted, comment) != 0))
		goto out;

	/* Allocate space for the private part of the key in the buffer. */
	if ((r = sshbuf_reserve(encrypted, sshbuf_len(buffer), &cp)) != 0)
		goto out;

	if ((r = cipher_set_key_string(&ciphercontext, cipher, passphrase,
	    CIPHER_ENCRYPT)) != 0)
		goto out;
	if ((r = cipher_crypt(&ciphercontext, cp,
	    sshbuf_ptr(buffer), sshbuf_len(buffer), 0, 0)) != 0)
		goto out;
	if ((r = cipher_cleanup(&ciphercontext)) != 0)
		goto out;

	r = sshbuf_putb(blob, encrypted);

 out:
	bzero(&ciphercontext, sizeof(ciphercontext));
	bzero(buf, sizeof(buf));
	if (buffer != NULL)
		sshbuf_free(buffer);
	if (encrypted != NULL)
		sshbuf_free(encrypted);

	return r;
}

/* convert SSH v2 key in OpenSSL PEM format */
static int
sshkey_private_pem_to_blob(struct sshkey *key, struct sshbuf *blob,
    const char *_passphrase, const char *comment)
{
	int success, r;
	int blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : NULL;
	const EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : NULL;
	const u_char *bptr;
	BIO *bio = NULL;

	if (len > 0 && len <= 4)
		return SSH_ERR_PASSPHRASE_TOO_SHORT;
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	switch (key->type) {
	case KEY_DSA:
		success = PEM_write_bio_DSAPrivateKey(bio, key->dsa,
		    cipher, passphrase, len, NULL, NULL);
		break;
	case KEY_ECDSA:
		success = PEM_write_bio_ECPrivateKey(bio, key->ecdsa,
		    cipher, passphrase, len, NULL, NULL);
		break;
	case KEY_RSA:
		success = PEM_write_bio_RSAPrivateKey(bio, key->rsa,
		    cipher, passphrase, len, NULL, NULL);
		break;
	default:
		success = 0;
		break;
	}
	if (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshbuf_put(blob, bptr, blen)) != 0)
		goto out;
	r = 0;
 out:
	BIO_free(bio);
	return r;
}

/* Save a key blob to a file */
static int
sshkey_save_private_blob(struct sshbuf *keybuf, const char *filename)
{
	int fd;

	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
		return SSH_ERR_SYSTEM_ERROR;
	if (atomicio(vwrite, fd, (u_char *)sshbuf_ptr(keybuf),
	    sshbuf_len(keybuf)) != sshbuf_len(keybuf)) {
		close(fd);
		unlink(filename);
		return SSH_ERR_SYSTEM_ERROR;
	}
	close(fd);
	return 0;
}

/* Serialise "key" to buffer "blob" */
static int
sshkey_private_to_blob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment)
{
	switch (key->type) {
	case KEY_RSA1:
		return sshkey_private_rsa1_to_blob(key, blob,
		    passphrase, comment);
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_RSA:
		return sshkey_private_pem_to_blob(key, blob,
		    passphrase, comment);
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
}

int
sshkey_save_private(struct sshkey *key, const char *filename,
    const char *passphrase, const char *comment)
{
	struct sshbuf *keyblob = NULL;
	int r;

	if ((keyblob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_private_to_blob(key, keyblob, passphrase,
	    comment)) != 0)
		goto out;
	if ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	return r;
}

/*
 * Parse the public, unencrypted portion of a RSA1 key.
 */
int
sshkey_parse_public_rsa1(struct sshbuf *blob,
    struct sshkey **keyp, char **commentp)
{
	int r;
	struct sshkey *pub = NULL;
	struct sshbuf *copy = NULL;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* Check that it is at least big enough to contain the ID string. */
	if (sshbuf_len(blob) < sizeof(authfile_id_string))
		return SSH_ERR_INVALID_FORMAT;

	/*
	 * Make sure it begins with the id string.  Consume the id string
	 * from the buffer.
	 */
	if (memcmp(sshbuf_ptr(blob), authfile_id_string,
	    sizeof(authfile_id_string)) != 0)
		return SSH_ERR_INVALID_FORMAT;
	/* Make a working copy of the keyblob and skip past the magic */
	if ((copy = sshbuf_fromb(blob)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_consume(copy, sizeof(authfile_id_string))) != 0)
		goto out;

	/* Skip cipher type, reserved data and key bits. */
	if ((r = sshbuf_get_u8(copy, NULL)) != 0 ||	/* cipher type */
	    (r = sshbuf_get_u32(copy, NULL)) != 0 ||	/* reserved */
	    (r = sshbuf_get_u32(copy, NULL)) != 0)	/* key bits */
		goto out;

	/* Read the public key from the buffer. */
	if ((pub = sshkey_new(KEY_RSA1)) == NULL ||
	    (r = sshbuf_get_bignum1(copy, pub->rsa->n)) != 0 ||
	    (r = sshbuf_get_bignum1(copy, pub->rsa->e)) != 0)
		goto out;

	/* Finally, the comment */
	if ((r = sshbuf_get_string(copy, (u_char**)commentp, NULL)) != 0)
		goto out;

	/* The encrypted private part is not parsed by this function. */

	r = 0;
	*keyp = pub;
	pub = NULL;

 out:
	if (copy != NULL)
		sshbuf_free(copy);
	if (pub != NULL)
		sshkey_free(pub);
	return r;
}

/* Load a key from a fd into a buffer */
int
sshkey_load_file(int fd, const char *filename, struct sshbuf *blob)
{
	u_char buf[1024];
	size_t len;
	struct stat st;
	int r;

	if (fstat(fd, &st) < 0)
		return SSH_ERR_SYSTEM_ERROR;
	if ((st.st_mode & (S_IFSOCK|S_IFCHR|S_IFIFO)) == 0 &&
	    st.st_size > MAX_KEY_FILE_SIZE)
		return SSH_ERR_INVALID_FORMAT;
	for (;;) {
		if ((len = atomicio(read, fd, buf, sizeof(buf))) == 0) {
			if (errno == EPIPE)
				break;
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		}
		if ((r = sshbuf_put(blob, buf, len)) != 0)
			goto out;
		if (sshbuf_len(blob) > MAX_KEY_FILE_SIZE) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	if ((st.st_mode & (S_IFSOCK|S_IFCHR|S_IFIFO)) == 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		goto out;
	}
	r = 0;

 out:
	bzero(buf, sizeof(buf));
	if (r != 0)
		sshbuf_reset(blob);
	return r;
}

/*
 * Loads the public part of the ssh v1 key file.  Returns NULL if an error was
 * encountered (the file does not exist or is not readable), and the key
 * otherwise.
 */
static int
sshkey_load_public_rsa1(int fd, const char *filename,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	int r;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((buffer = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_load_file(fd, filename, buffer)) != 0)
		goto out;
	if ((r = sshkey_parse_public_rsa1(buffer, keyp, commentp)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(buffer);
	return r;
}

static int
sshkey_parse_private_rsa1(struct sshbuf *blob, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	int r;
	u_int16_t check1, check2;
	u_int8_t cipher_type;
	struct sshbuf *decrypted = NULL, *copy = NULL;
	u_char *cp;
	char *comment = NULL;
	struct sshcipher_ctx ciphercontext;
	const struct sshcipher *cipher;
	struct sshkey *prv = NULL;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* Check that it is at least big enough to contain the ID string. */
	if (sshbuf_len(blob) < sizeof(authfile_id_string))
		return SSH_ERR_INVALID_FORMAT;

	/*
	 * Make sure it begins with the id string.  Consume the id string
	 * from the buffer.
	 */
	if (memcmp(sshbuf_ptr(blob), authfile_id_string,
	    sizeof(authfile_id_string)) != 0)
		return SSH_ERR_INVALID_FORMAT;

	if ((prv = sshkey_new_private(KEY_RSA1)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((copy = sshbuf_fromb(blob)) == NULL ||
	    (decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_consume(copy, sizeof(authfile_id_string))) != 0)
		goto out;

	/* Read cipher type. */
	if ((r = sshbuf_get_u8(copy, &cipher_type)) != 0 ||
	    (r = sshbuf_get_u32(copy, NULL)) != 0)	/* reserved */
		goto out;

	/* Read the public key and comment from the buffer. */
	if ((r = sshbuf_get_u32(copy, NULL)) != 0 ||	/* key bits */
	    (r = sshbuf_get_bignum1(copy, prv->rsa->n)) != 0 ||
	    (r = sshbuf_get_bignum1(copy, prv->rsa->e)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &comment, NULL)) != 0)
		goto out;

	/* Check that it is a supported cipher. */
	cipher = cipher_by_number(cipher_type);
	if (cipher == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	/* Initialize space for decrypted data. */
	if ((r = sshbuf_reserve(decrypted, sshbuf_len(copy), &cp)) != 0)
		goto out;

	/* Rest of the buffer is encrypted.  Decrypt it using the passphrase. */
	if ((r = cipher_set_key_string(&ciphercontext, cipher, passphrase,
	    CIPHER_DECRYPT)) != 0)
		goto out;
	if ((r = cipher_crypt(&ciphercontext, cp,
	    sshbuf_ptr(copy), sshbuf_len(copy), 0, 0)) != 0) {
		cipher_cleanup(&ciphercontext);
		goto out;
	}
	if ((r = cipher_cleanup(&ciphercontext)) != 0)
		goto out;

	if ((r = sshbuf_get_u16(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u16(decrypted, &check2)) != 0)
		goto out;
	if (check1 != check2) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	/* Read the rest of the private key. */
	if ((r = sshbuf_get_bignum1(decrypted, prv->rsa->d)) != 0 ||
	    (r = sshbuf_get_bignum1(decrypted, prv->rsa->iqmp)) != 0 ||
	    (r = sshbuf_get_bignum1(decrypted, prv->rsa->q)) != 0 ||
	    (r = sshbuf_get_bignum1(decrypted, prv->rsa->p)) != 0)
		goto out;

	/* calculate p-1 and q-1 */
	if ((r = rsa_generate_additional_parameters(prv->rsa)) != 0)
		goto out;

	/* enable blinding */
	if (RSA_blinding_on(prv->rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	r = 0;
	*keyp = prv;
	prv = NULL;
	if (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	bzero(&ciphercontext, sizeof(ciphercontext));
	if (comment != NULL)
		free(comment);
	if (prv != NULL)
		sshkey_free(prv);
	if (copy != NULL)
		sshbuf_free(copy);
	if (decrypted != NULL)
		sshbuf_free(decrypted);
	return r;
}

static int
sshkey_parse_private_pem(struct sshbuf *blob, int type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	EVP_PKEY *pk = NULL;
	struct sshkey *prv = NULL;
	char *name = "<no key>";
	BIO *bio = NULL;
	int r;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((bio = BIO_new(BIO_s_mem())) == NULL || sshbuf_len(blob) > INT_MAX)
		return SSH_ERR_ALLOC_FAIL;
	if (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (int)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	
	if ((pk = PEM_read_bio_PrivateKey(bio, NULL, NULL,
	    (char *)passphrase)) == NULL) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	if (pk->type == EVP_PKEY_RSA &&
	    (type == KEY_UNSPEC || type == KEY_RSA)) {
		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		prv->rsa = EVP_PKEY_get1_RSA(pk);
		prv->type = KEY_RSA;
		name = "rsa w/o comment";
#ifdef DEBUG_PK
		RSA_print_fp(stderr, prv->rsa, 8);
#endif
		if (RSA_blinding_on(prv->rsa, NULL) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	} else if (pk->type == EVP_PKEY_DSA &&
	    (type == KEY_UNSPEC || type == KEY_DSA)) {
		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		prv->dsa = EVP_PKEY_get1_DSA(pk);
		prv->type = KEY_DSA;
		name = "dsa w/o comment";
#ifdef DEBUG_PK
		DSA_print_fp(stderr, prv->dsa, 8);
#endif
	} else if (pk->type == EVP_PKEY_EC &&
	    (type == KEY_UNSPEC || type == KEY_ECDSA)) {
		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		prv->ecdsa = EVP_PKEY_get1_EC_KEY(pk);
		prv->type = KEY_ECDSA;
		prv->ecdsa_nid = sshkey_ecdsa_key_to_nid(prv->ecdsa);
		if (prv->ecdsa_nid == -1 ||
		    sshkey_curve_nid_to_name(prv->ecdsa_nid) == NULL ||
		    sshkey_ec_validate_public(EC_KEY_get0_group(prv->ecdsa),
		    EC_KEY_get0_public_key(prv->ecdsa)) != 0 ||
		    sshkey_ec_validate_private(prv->ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		name = "ecdsa w/o comment";
#ifdef DEBUG_PK
		if (prv != NULL && prv->ecdsa != NULL)
			sshkey_dump_ec_key(prv->ecdsa);
#endif
	} else {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (commentp != NULL &&
	    (*commentp = strdup(name)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	r = 0;
	*keyp = prv;
	prv = NULL;
 out:
	BIO_free(bio);
	if (pk != NULL)
		EVP_PKEY_free(pk);
	if (prv != NULL)
		sshkey_free(prv);
	return r;
}

int
sshkey_load_private_pem(int fd, int type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	int r;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((buffer = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_load_file(fd, NULL, buffer)) != 0)
		goto out;
	if ((r = sshkey_parse_private_pem(buffer, type, passphrase,
	    keyp, commentp)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(buffer);
	return r;
}

/* XXX remove error() calls from here? */
int
sshkey_perm_ok(int fd, const char *filename)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return 0;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
	if ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is recommended that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		return 0;
	}
	return 1;
}

static int
sshkey_parse_private_type(struct sshbuf *blob, int type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	switch (type) {
	case KEY_RSA1:
		return sshkey_parse_private_rsa1(blob, passphrase,
		    keyp, commentp);
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_RSA:
	case KEY_UNSPEC:
		return sshkey_parse_private_pem(blob, type, passphrase,
		    keyp, commentp);
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
}

/* XXX kill perm_ok now that we have SSH_ERR_KEY_BAD_PERMISSIONS? */
int
sshkey_load_private_type(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp, int *perm_ok)
{
	int fd, r;
	struct sshbuf *buffer = NULL;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		if (perm_ok != NULL)
			*perm_ok = 0;
		return SSH_ERR_SYSTEM_ERROR;
	}
	if (!sshkey_perm_ok(fd, filename)) {
		if (perm_ok != NULL)
			*perm_ok = 0;
		r = SSH_ERR_KEY_BAD_PERMISSIONS;
		goto out;
	}
	if (perm_ok != NULL)
		*perm_ok = 1;

	if ((buffer = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_load_file(fd, filename, buffer)) != 0)
		goto out;
	if ((r = sshkey_parse_private_type(buffer, type, passphrase,
	    keyp, commentp)) != 0)
		goto out;
	r = 0;
 out:
	close(fd);
	if (buffer != NULL)
		sshbuf_free(buffer);
	return r;
}

int
sshkey_parse_private(struct sshbuf *buffer, const char *passphrase,
    const char *filename, struct sshkey **keyp, char **commentp)
{
	struct sshkey *key;
	int r;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* it's a SSH v1 key if the public key part is readable */
	if ((r = sshkey_parse_public_rsa1(buffer, &key, NULL)) == 0) {
		sshkey_free(key);
		return sshkey_parse_private_type(buffer, KEY_RSA1, passphrase,
		    keyp, commentp);
	}
	if ((r = sshkey_parse_private_type(buffer, KEY_UNSPEC,
	    passphrase, &key, NULL)) != 0)
		return r;
	if (commentp != NULL &&
	    (*commentp = strdup(filename)) == NULL) {
		sshkey_free(key);
		return SSH_ERR_ALLOC_FAIL;
	}
	*keyp = key;
	return 0;
}

/* XXX this is almost identical to sshkey_load_private_type() */
int
sshkey_load_private(const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	int r, fd;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return SSH_ERR_SYSTEM_ERROR;
	if (!sshkey_perm_ok(fd, filename)) {
		r = SSH_ERR_KEY_BAD_PERMISSIONS;
		goto out;
	}

	if ((buffer = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_load_file(fd, filename, buffer)) != 0 ||
	    (r = sshkey_parse_private(buffer, passphrase, filename,
	    keyp, commentp)) != 0)
		goto out;
	r = 0;
 out:
	close(fd);
	if (buffer != NULL)
		sshbuf_free(buffer);
	return r;
}

static int
sshkey_try_load_public(struct sshkey *k, const char *filename, char **commentp)
{
	FILE *f;
	char line[SSH_MAX_PUBKEY_BYTES];
	char *cp;
	u_long linenum = 0;
	int r;

	if (commentp != NULL)
		*commentp = NULL;
	if ((f = fopen(filename, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;
	while (read_keyfile_line(f, filename, line, sizeof(line),
		    &linenum) != -1) {
		cp = line;
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}
		/* Abort loading if this looks like a private key */
		if (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, authfile_id_string) == 0)
			break;
		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		if (*cp) {
			if ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				if (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					if (*commentp == NULL)
						r = SSH_ERR_ALLOC_FAIL;
				}
				fclose(f);
				return r;
			}
		}
	}
	fclose(f);
	return SSH_ERR_INVALID_FORMAT;
}

/* load public key from ssh v1 private or any pubkey file */
int
sshkey_load_public(const char *filename, struct sshkey **keyp, char **commentp)
{
	struct sshkey *pub = NULL;
	char file[MAXPATHLEN];
	int r, fd;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* try rsa1 private key */
	if ((fd = open(filename, O_RDONLY)) < 0)
		goto skip;
	r = sshkey_load_public_rsa1(fd, filename, keyp, commentp);
	close(fd);
	switch (r) {
	case SSH_ERR_INTERNAL_ERROR:
	case SSH_ERR_ALLOC_FAIL:
	case SSH_ERR_SYSTEM_ERROR:
	case 0:
		return r;
	}

	/* try rsa1 public key */
	if ((pub = sshkey_new(KEY_RSA1)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_try_load_public(pub, filename, commentp)) == 0) {
		*keyp = pub;
		return 0;
	}
	sshkey_free(pub);

	/* try ssh2 public key */
	if ((pub = sshkey_new(KEY_UNSPEC)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_try_load_public(pub, filename, commentp)) == 0) {
		*keyp = pub;
		return 0;
	}

 skip:
	/* try .pub suffix */
	if (pub == NULL && (pub = sshkey_new(KEY_UNSPEC)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	r = SSH_ERR_ALLOC_FAIL;	/* in case strlcpy or strlcat fail */
	if ((strlcpy(file, filename, sizeof file) < sizeof(file)) &&
	    (strlcat(file, ".pub", sizeof file) < sizeof(file)) &&
	    (r = sshkey_try_load_public(pub, file, commentp)) == 0) {
		*keyp = pub;
		return 0;
	}
	sshkey_free(pub);
	return r;
}

/* Load the certificate associated with the named private key */
int
sshkey_load_cert(const char *filename, struct sshkey **keyp)
{
	struct sshkey *pub = NULL;
	char *file = NULL;
	int r;

	*keyp = NULL;

	if (asprintf(&file, "%s-cert.pub", filename) == -1)
		return SSH_ERR_ALLOC_FAIL;

	if ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_try_load_public(pub, file, NULL)) != 0)
		goto out;

	*keyp = pub;
	pub = NULL;
	r = 0;

 out:
	if (file != NULL)
		free(file);
	if (pub != NULL)
		sshkey_free(pub);
	return r;
}

/* Load private key and certificate */
int
sshkey_load_private_cert(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp, int *perm_ok)
{
	struct sshkey *key = NULL, *cert = NULL;
	int r;

	*keyp = NULL;

	switch (type) {
	case KEY_RSA:
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_UNSPEC:
		break;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	if ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, NULL, perm_ok)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		goto out;

	/* Make sure the private key matches the certificate */
	if (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}

	if ((r = sshkey_to_certified(key, sshkey_cert_is_legacy(cert))) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		goto out;
	r = 0;
	*keyp = key;
	key = NULL;
 out:
	if (key != NULL)
		sshkey_free(key);
	if (cert != NULL)
		sshkey_free(cert);
	return r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If strict_type is set then the key type must match exactly,
 * otherwise a comparison that ignores certficiate data is performed.
 */
int
sshkey_in_file(struct sshkey *key, const char *filename, int strict_type)
{
	FILE *f;
	char line[SSH_MAX_PUBKEY_BYTES];
	char *cp;
	u_long linenum = 0;
	int r = 0;
	struct sshkey *pub = NULL;
	int (*sshkey_compare)(const struct sshkey *, const struct sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	if ((f = fopen(filename, "r")) == NULL) {
		if (errno == ENOENT)
			return SSH_ERR_KEY_NOT_FOUND;
		else
			return SSH_ERR_SYSTEM_ERROR;
	}

	while (read_keyfile_line(f, filename, line, sizeof(line),
	    &linenum) != -1) {
		cp = line;

		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}

		if ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((r = sshkey_read(pub, &cp)) != 0)
			goto out;
		if (sshkey_compare(key, pub)) {
			r = 0;
			goto out;
		}
		sshkey_free(pub);
		pub = NULL;
	}
	r = SSH_ERR_KEY_NOT_FOUND;
 out:
	if (pub != NULL)
		sshkey_free(pub);
	fclose(f);
	return r;
}

