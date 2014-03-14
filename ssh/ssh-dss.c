/* $OpenBSD: ssh-dss.c,v 1.28 2013/05/17 00:13:14 djm Exp $ */
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

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "err.h"
#define SSHKEY_INTERNAL
#include "key.h"

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

int
ssh_dss_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	DSA_SIG *sig = NULL;
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX md;
	u_char digest[EVP_MAX_MD_SIZE], sigblob[SIGBLOB_LEN];
	size_t rlen, slen, len;
	u_int dlen;
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INVALID_ARGUMENT;

	if (key == NULL || key->dsa == NULL || (key->type != KEY_DSA &&
	    key->type != KEY_DSA_CERT && key->type != KEY_DSA_CERT_V00))
		return SSH_ERR_INVALID_ARGUMENT;
	if (EVP_DigestInit(&md, evp_md) != 1 ||
	    EVP_DigestUpdate(&md, data, datalen) != 1 ||
	    EVP_DigestFinal(&md, digest, &dlen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((sig = DSA_do_sign(digest, dlen, key->dsa)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	rlen = BN_num_bytes(sig->r);
	slen = BN_num_bytes(sig->s);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	bzero(sigblob, SIGBLOB_LEN);
	BN_bn2bin(sig->r, sigblob + SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(sig->s, sigblob + SIGBLOB_LEN - slen);

	if (compat & SSH_BUG_SIGBLOB) {
		if (lenp != NULL)
			*lenp = SIGBLOB_LEN;
		if (sigp != NULL) {
			if ((*sigp = malloc(SIGBLOB_LEN)) == NULL) {
				ret = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
			memcpy(*sigp, sigblob, SIGBLOB_LEN);
		}
		ret = 0;
	} else {
		/* ietf-drafts */
		if ((b = sshbuf_new()) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((ret = sshbuf_put_cstring(b, "ssh-dss")) != 0 ||
		    (ret = sshbuf_put_string(b, sigblob, SIGBLOB_LEN)) != 0)
			goto out;
		len = sshbuf_len(b);
		if (lenp != NULL)
			*lenp = len;
		if (sigp != NULL) {
			if ((*sigp = malloc(len)) == NULL) {
				ret = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
			memcpy(*sigp, sshbuf_ptr(b), len);
		}
		ret = 0;
	}
 out:
	bzero(&md, sizeof(md));
	bzero(digest, sizeof(digest));
	if (sig != NULL)
		DSA_SIG_free(sig);
	if (b != NULL)
		sshbuf_free(b);
	return ret;
}

int
ssh_dss_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	DSA_SIG *sig = NULL;
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX md;
	u_char digest[EVP_MAX_MD_SIZE], *sigblob = NULL;
	size_t len;
	u_int dlen;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *ktype = NULL;

	if (key == NULL || key->dsa == NULL || (key->type != KEY_DSA &&
	    key->type != KEY_DSA_CERT && key->type != KEY_DSA_CERT_V00))
		return SSH_ERR_INVALID_ARGUMENT;

	/* fetch signature */
	if (compat & SSH_BUG_SIGBLOB) {
		if ((sigblob = malloc(signaturelen)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		memcpy(sigblob, signature, signaturelen);
		len = signaturelen;
	} else {
		/* ietf-drafts */
		if ((b = sshbuf_from(signature, signaturelen)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
		    sshbuf_get_string(b, &sigblob, &len) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if (strcmp("ssh-dss", ktype) != 0) {
			ret = SSH_ERR_KEY_TYPE_MISMATCH;
			goto out;
		}
		if (sshbuf_len(b) != 0) {
			ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
			goto out;
		}
	}

	if (len != SIGBLOB_LEN) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* parse signature */
	if ((sig = DSA_SIG_new()) == NULL ||
	    (sig->r = BN_new()) == NULL ||
	    (sig->s = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, sig->r) == NULL) ||
	    (BN_bin2bn(sigblob+ INTBLOB_LEN, INTBLOB_LEN, sig->s) == NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* sha1 the data */
	if (EVP_DigestInit(&md, evp_md) != 1 ||
	    EVP_DigestUpdate(&md, data, datalen) != 1 ||
	    EVP_DigestFinal(&md, digest, &dlen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	switch (DSA_do_verify(digest, dlen, sig, key->dsa)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

 out:
	bzero(digest, sizeof(digest));
	bzero(&md, sizeof(md));
	if (sig != NULL)
		DSA_SIG_free(sig);
	if (b != NULL)
		sshbuf_free(b);
	if (ktype != NULL)
		free(ktype);
	if (sigblob != NULL) {
		memset(sigblob, 0, len);
		free(sigblob);
	}
	return ret;
}
