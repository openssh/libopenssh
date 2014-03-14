/* $OpenBSD: key.c,v 1.104 2013/05/19 02:42:42 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
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

#include <sys/param.h>
#include <sys/types.h>

#include <openssl/evp.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "ssh2.h"
#include "err.h"
#include "misc.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "key.h"

struct keytype {
	char *name;
	char *shortname;
	int type;
	int nid;
	int cert;
};
static const struct keytype keytypes[] = {
	{ NULL, "RSA1", KEY_RSA1, 0, 0 },
	{ "ssh-rsa", "RSA", KEY_RSA, 0, 0 },
	{ "ssh-dss", "DSA", KEY_DSA, 0, 0 },
	{ "ecdsa-sha2-nistp256", "ECDSA", KEY_ECDSA, NID_X9_62_prime256v1, 0 },
	{ "ecdsa-sha2-nistp384", "ECDSA", KEY_ECDSA, NID_secp384r1, 0 },
	{ "ecdsa-sha2-nistp521", "ECDSA", KEY_ECDSA, NID_secp521r1, 0 },
	{ "ssh-rsa-cert-v01@openssh.com", "RSA-CERT", KEY_RSA_CERT, 0, 1 },
	{ "ssh-dss-cert-v01@openssh.com", "DSA-CERT", KEY_DSA_CERT, 0, 1 },
	{ "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ECDSA-CERT",
	    KEY_ECDSA_CERT, NID_X9_62_prime256v1, 1 },
	{ "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ECDSA-CERT",
	    KEY_ECDSA_CERT, NID_secp384r1, 1 },
	{ "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ECDSA-CERT",
	    KEY_ECDSA_CERT, NID_secp521r1, 1 },
	{ "ssh-rsa-cert-v00@openssh.com", "RSA-CERT-V00",
	    KEY_RSA_CERT_V00, 0, 1 },
	{ "ssh-dss-cert-v00@openssh.com", "DSA-CERT-V00",
	    KEY_DSA_CERT_V00, 0, 1 },
	{ NULL, NULL, -1, -1, 0 }
};

const char *
sshkey_type(const struct sshkey *k)
{
	const struct keytype *kt;

	for (kt = keytypes; kt->type != -1; kt++) {
		if (kt->type == k->type)
			return kt->shortname;
	}
	return "unknown";
}

static const char *
sshkey_ssh_name_from_type_nid(int type, int nid)
{
	const struct keytype *kt;

	for (kt = keytypes; kt->type != -1; kt++) {
		if (kt->type == type && (kt->nid == 0 || kt->nid == nid))
			return kt->name;
	}
	return "ssh-unknown";
}

const char *
sshkey_ssh_name(const struct sshkey *k)
{
	return sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_ssh_name_plain(const struct sshkey *k)
{
	return sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

int
sshkey_type_from_name(const char *name)
{
	const struct keytype *kt;

	for (kt = keytypes; kt->type != -1; kt++) {
		/* Only allow shortname matches for plain key types */
		if ((kt->name != NULL && strcmp(name, kt->name) == 0) ||
		    (!kt->cert && strcasecmp(kt->shortname, name) == 0))
			return kt->type;
	}
	return KEY_UNSPEC;
}

int
sshkey_ecdsa_nid_from_name(const char *name)
{
	const struct keytype *kt;

        for (kt = keytypes; kt->type != -1; kt++) {
                if (kt->type != KEY_ECDSA && kt->type != KEY_ECDSA_CERT)
                        continue;
                if (kt->name != NULL && strcmp(name, kt->name) == 0)
                        return kt->nid;
        }
	return -1;
}

char *
sshkey_alg_list(void)
{
	char *ret = NULL;
	size_t nlen, rlen = 0;
	const struct keytype *kt;

	for (kt = keytypes; kt->type != -1; kt++) {
		if (kt->name == NULL)
			continue;
		if (ret != NULL)
			ret[rlen++] = '\n';
		nlen = strlen(kt->name);
		if (reallocn((void **)&ret, 1, rlen + nlen + 2) != 0)
			return NULL;
		memcpy(ret + rlen, kt->name, nlen + 1);
		rlen += nlen;
	}
	return ret;
}

u_int
sshkey_size(const struct sshkey *k)
{
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		return BN_num_bits(k->rsa->n);
	case KEY_DSA:
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		return BN_num_bits(k->dsa->p);
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
		return sshkey_curve_nid_to_bits(k->ecdsa_nid);
	}
	return 0;
}

int
sshkey_cert_is_legacy(const struct sshkey *k)
{
	switch (k->type) {
	case KEY_DSA_CERT_V00:
	case KEY_RSA_CERT_V00:
		return 1;
	default:
		return 0;
	}
}

/* XXX: these are really begging for a table-driven approach */
int
sshkey_curve_name_to_nid(const char *name)
{
	if (strcmp(name, "nistp256") == 0)
		return NID_X9_62_prime256v1;
	else if (strcmp(name, "nistp384") == 0)
		return NID_secp384r1;
	else if (strcmp(name, "nistp521") == 0)
		return NID_secp521r1;
	else
		return -1;
}

u_int
sshkey_curve_nid_to_bits(int nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		return 256;
	case NID_secp384r1:
		return 384;
	case NID_secp521r1:
		return 521;
	default:
		return 0;
	}
}

const char *
sshkey_curve_nid_to_name(int nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		return "nistp256";
	case NID_secp384r1:
		return "nistp384";
	case NID_secp521r1:
		return "nistp521";
	default:
		return NULL;
	}
}

const EVP_MD *
sshkey_ec_nid_to_evpmd(int nid)
{
	int kbits = sshkey_curve_nid_to_bits(nid);

	if (kbits <= 0)
		return NULL;

	/* RFC5656 section 6.2.1 */
	if (kbits <= 256)
		return EVP_sha256();
	else if (kbits <= 384)
		return EVP_sha384();
	else
		return EVP_sha512();
}

static struct sshkey_cert *
cert_new(void)
{
	struct sshkey_cert *cert;

	if ((cert = calloc(1, sizeof(*cert))) == NULL)
		return NULL;
	if ((cert->certblob = sshbuf_new()) == NULL ||
	    (cert->critical = sshbuf_new()) == NULL ||
	    (cert->extensions = sshbuf_new()) == NULL) {
		free(cert);
		return NULL;
	}
	cert->key_id = NULL;
	cert->principals = NULL;
	cert->signature_key = NULL;
	return cert;
}

struct sshkey *
sshkey_new(int type)
{
	struct sshkey *k;
	RSA *rsa;
	DSA *dsa;

	if ((k = calloc(1, sizeof(*k))) == NULL)
		return NULL;
	k->type = type;
	k->ecdsa = NULL;
	k->ecdsa_nid = -1;
	k->dsa = NULL;
	k->rsa = NULL;
	k->cert = NULL;
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		if ((rsa = RSA_new()) == NULL ||
		    (rsa->n = BN_new()) == NULL ||
		    (rsa->e = BN_new()) == NULL) {
			if (rsa != NULL)
				RSA_free(rsa);
			free(k);
			return NULL;
		}
		k->rsa = rsa;
		break;
	case KEY_DSA:
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		if ((dsa = DSA_new()) == NULL ||
		    (dsa->p = BN_new()) == NULL ||
		    (dsa->q = BN_new()) == NULL ||
		    (dsa->g = BN_new()) == NULL ||
		    (dsa->pub_key = BN_new()) == NULL) {
			if (dsa != NULL)
				DSA_free(dsa);
			free(k);
			return NULL;
		}
		k->dsa = dsa;
		break;
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
		/* Cannot do anything until we know the group */
		break;
	case KEY_UNSPEC:
		break;
	default:
		free(k);
		return NULL;
		break;
	}

	if (sshkey_is_cert(k)) {
		if ((k->cert = cert_new()) == NULL) {
			sshkey_free(k);
			return NULL;
		}
	}

	return k;
}

int
sshkey_add_private(struct sshkey *k)
{
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		if ((k->rsa->d = BN_new()) == NULL ||
		    (k->rsa->iqmp = BN_new()) == NULL ||
		    (k->rsa->q = BN_new()) == NULL ||
		    (k->rsa->p = BN_new()) == NULL ||
		    (k->rsa->dmq1 = BN_new()) == NULL ||
		    (k->rsa->dmp1 = BN_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		break;
	case KEY_DSA:
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		if ((k->dsa->priv_key = BN_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		break;
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
		/* Cannot do anything until we know the group */
		break;
	case KEY_UNSPEC:
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	return 0;
}

struct sshkey *
sshkey_new_private(int type)
{
	struct sshkey *k = sshkey_new(type);

	if (k == NULL)
		return NULL;
	if (sshkey_add_private(k) != 0) {
		sshkey_free(k);
		return NULL;
	}
	return k;
}

static void
cert_free(struct sshkey_cert *cert)
{
	u_int i;

	if (cert == NULL)
		return;
	if (cert->certblob != NULL)
		sshbuf_free(cert->certblob);
	if (cert->critical != NULL)
		sshbuf_free(cert->critical);
	if (cert->extensions != NULL)
		sshbuf_free(cert->extensions);
	if (cert->key_id != NULL)
		free(cert->key_id);
	for (i = 0; i < cert->nprincipals; i++)
		free(cert->principals[i]);
	if (cert->principals != NULL)
		free(cert->principals);
	if (cert->signature_key != NULL)
		sshkey_free(cert->signature_key);
	bzero(cert, sizeof(*cert));
	free(cert);
}

void
sshkey_free(struct sshkey *k)
{
	if (k == NULL)
		return;
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		if (k->rsa != NULL)
			RSA_free(k->rsa);
		k->rsa = NULL;
		break;
	case KEY_DSA:
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		if (k->dsa != NULL)
			DSA_free(k->dsa);
		k->dsa = NULL;
		break;
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
		if (k->ecdsa != NULL)
			EC_KEY_free(k->ecdsa);
		k->ecdsa = NULL;
		break;
	case KEY_UNSPEC:
		break;
	default:
		break;
	}
	if (sshkey_is_cert(k))
		cert_free(k->cert);
	bzero(k, sizeof(*k));
	free(k);
}

static int
cert_compare(struct sshkey_cert *a, struct sshkey_cert *b)
{
	if (a == NULL && b == NULL)
		return 1;
	if (a == NULL || b == NULL)
		return 0;
	if (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		return 0;
	if (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		return 0;
	return 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
int
sshkey_equal_public(const struct sshkey *a, const struct sshkey *b)
{
	BN_CTX *bnctx;

	if (a == NULL || b == NULL ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		return 0;

	switch (a->type) {
	case KEY_RSA1:
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
	case KEY_RSA:
		return a->rsa != NULL && b->rsa != NULL &&
		    BN_cmp(a->rsa->e, b->rsa->e) == 0 &&
		    BN_cmp(a->rsa->n, b->rsa->n) == 0;
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
	case KEY_DSA:
		return a->dsa != NULL && b->dsa != NULL &&
		    BN_cmp(a->dsa->p, b->dsa->p) == 0 &&
		    BN_cmp(a->dsa->q, b->dsa->q) == 0 &&
		    BN_cmp(a->dsa->g, b->dsa->g) == 0 &&
		    BN_cmp(a->dsa->pub_key, b->dsa->pub_key) == 0;
	case KEY_ECDSA_CERT:
	case KEY_ECDSA:
		if (a->ecdsa == NULL || b->ecdsa == NULL ||
		    EC_KEY_get0_public_key(a->ecdsa) == NULL ||
		    EC_KEY_get0_public_key(b->ecdsa) == NULL)
			return 0;
		if ((bnctx = BN_CTX_new()) == NULL)
			return 0;
		if (EC_GROUP_cmp(EC_KEY_get0_group(a->ecdsa),
		    EC_KEY_get0_group(b->ecdsa), bnctx) != 0 ||
		    EC_POINT_cmp(EC_KEY_get0_group(a->ecdsa),
		    EC_KEY_get0_public_key(a->ecdsa),
		    EC_KEY_get0_public_key(b->ecdsa), bnctx) != 0) {
			BN_CTX_free(bnctx);
			return 0;
		}
		BN_CTX_free(bnctx);
		return 1;
	default:
		return 0;
	}
	/* NOTREACHED */
}

int
sshkey_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a == NULL || b == NULL || a->type != b->type)
		return 0;
	if (sshkey_is_cert(a)) {
		if (!cert_compare(a->cert, b->cert))
			return 0;
	}
	return sshkey_equal_public(a, b);
}

static int
to_blob_buf(const struct sshkey *key, struct sshbuf *b, int force_plain)
{
	int type, ret = SSH_ERR_INTERNAL_ERROR;
	const char *typename;

	if (key == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(key->type) : key->type;
	typename = sshkey_ssh_name_from_type_nid(type, key->ecdsa_nid);

	switch (type) {
	case KEY_DSA_CERT_V00:
	case KEY_RSA_CERT_V00:
	case KEY_DSA_CERT:
	case KEY_ECDSA_CERT:
	case KEY_RSA_CERT:
		/* Use the existing blob */
		/* XXX modified flag? */
		if ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			return ret;
		break;
	case KEY_DSA:
		if (key->dsa == NULL)
			return SSH_ERR_INVALID_ARGUMENT;
		if ((ret = sshbuf_put_cstring(b, typename)) != 0 ||
		    (ret = sshbuf_put_bignum2(b, key->dsa->p)) != 0 ||
		    (ret = sshbuf_put_bignum2(b, key->dsa->q)) != 0 ||
		    (ret = sshbuf_put_bignum2(b, key->dsa->g)) != 0 ||
		    (ret = sshbuf_put_bignum2(b, key->dsa->pub_key)) != 0)
			return ret;
		break;
	case KEY_ECDSA:
		if (key->ecdsa == NULL)
			return SSH_ERR_INVALID_ARGUMENT;
		if ((ret = sshbuf_put_cstring(b, typename)) != 0 ||
		    (ret = sshbuf_put_cstring(b,
		    sshkey_curve_nid_to_name(key->ecdsa_nid))) != 0 ||
		    (ret = sshbuf_put_eckey(b, key->ecdsa)) != 0)
			return ret;
		break;
	case KEY_RSA:
		if (key->rsa == NULL)
			return SSH_ERR_INVALID_ARGUMENT;
		if ((ret = sshbuf_put_cstring(b, typename)) != 0 ||
		    (ret = sshbuf_put_bignum2(b, key->rsa->e)) != 0 ||
		    (ret = sshbuf_put_bignum2(b, key->rsa->n)) != 0)
			return ret;
		break;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
	return 0;
}

int
sshkey_to_blob_buf(const struct sshkey *key, struct sshbuf *b)
{
	return to_blob_buf(key, b, 0);
}

int
sshkey_plain_to_blob_buf(const struct sshkey *key, struct sshbuf *b)
{
	return to_blob_buf(key, b, 1);
}

static int
to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp, int force_plain)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	struct sshbuf *b = NULL;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((ret = to_blob_buf(key, b, force_plain)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (lenp != NULL)
		*lenp = len;
	if (blobp != NULL) {
		if ((*blobp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	return ret;
}

int
sshkey_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	return to_blob(key, blobp, lenp, 0);
}

int
sshkey_plain_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	return to_blob(key, blobp, lenp, 1);
}

u_char*
sshkey_fingerprint_raw(const struct sshkey *k, enum sshkey_fp_type dgst_type,
    size_t *dgst_raw_length)
{
	const EVP_MD *md = NULL;
	EVP_MD_CTX ctx;
	u_char *blob;
	u_char *retval = NULL;
	size_t len = 0;
	int nlen, elen, force_plain = 0;
	u_int dlen;

	*dgst_raw_length = 0;

	switch (dgst_type) {
	case SSH_FP_MD5:
		md = EVP_md5();
		break;
	case SSH_FP_SHA1:
		md = EVP_sha1();
		break;
	case SSH_FP_SHA256:
		md = EVP_sha256();
		break;
	default:
		return NULL;
	}
	switch (k->type) {
	case KEY_RSA1:
		nlen = BN_num_bytes(k->rsa->n);
		elen = BN_num_bytes(k->rsa->e);
		len = nlen + elen;
		if ((blob = malloc(len)) == NULL)
			return NULL;
		BN_bn2bin(k->rsa->n, blob);
		BN_bn2bin(k->rsa->e, blob + nlen);
		break;
	case KEY_DSA_CERT_V00:
	case KEY_RSA_CERT_V00:
	case KEY_DSA_CERT:
	case KEY_ECDSA_CERT:
	case KEY_RSA_CERT:
		/* We want a fingerprint of the _key_ not of the cert */
		force_plain = 1;
		/* FALLTHROUGH */
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_RSA:
		if (to_blob(k, &blob, &len, force_plain) == -1)
			return NULL;
		break;
	case KEY_UNSPEC:
	default:
		return NULL;
	}
	if ((retval = malloc(EVP_MAX_MD_SIZE)) == NULL) {
		bzero(blob, len);
		free(blob);
		return NULL;
	}
	EVP_DigestInit(&ctx, md);
	EVP_DigestUpdate(&ctx, blob, len);
	EVP_DigestFinal(&ctx, retval, &dlen);
	*dgst_raw_length = dlen;
	bzero(blob, len);
	free(blob);
	return retval;
}

static char *
fingerprint_hex(u_char *dgst_raw, size_t dgst_raw_len)
{
	char *retval;
	size_t i;

	if ((retval = calloc(1, dgst_raw_len * 3 + 1)) == NULL)
		return NULL;
	for (i = 0; i < dgst_raw_len; i++) {
		char hex[4];
		snprintf(hex, sizeof(hex), "%02x:", dgst_raw[i]);
		strlcat(retval, hex, dgst_raw_len * 3 + 1);
	}

	/* Remove the trailing ':' character */
	retval[(dgst_raw_len * 3) - 1] = '\0';
	return retval;
}

static char *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	char vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	char consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	char *retval;

	rounds = (dgst_raw_len / 2) + 1;
	if ((retval = calloc(rounds, 6)) == NULL)
		return NULL;
	retval[j++] = 'x';
	for (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		if ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			if ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} else {
			idx0 = seed % 6;
			idx1 = 16;
			idx2 = seed / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	return retval;
}

/*
 * Draw an ASCII-Art representing the fingerprint so human brain can
 * profit from its built-in pattern recognition ability.
 * This technique is called "random art" and can be found in some
 * scientific publications like this original paper:
 *
 * "Hash Visualization: a New Technique to improve Real-World Security",
 * Perrig A. and Song D., 1999, International Workshop on Cryptographic
 * Techniques and E-Commerce (CrypTEC '99)
 * sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 *
 * The subject came up in a talk by Dan Kaminsky, too.
 *
 * If you see the picture is different, the key is different.
 * If the picture looks the same, you still know nothing.
 *
 * The algorithm used here is a worm crawling over a discrete plane,
 * leaving a trace (augmenting the field) everywhere it goes.
 * Movement is taken from dgst_raw 2bit-wise.  Bumping into walls
 * makes the respective movement vector be ignored for this turn.
 * Graphs are not unambiguous, because circles in graphs can be
 * walked in either direction.
 */

/*
 * Field sizes for the random art.  Have to be odd, so the starting point
 * can be in the exact middle of the picture, and FLDBASE should be >=8 .
 * Else pictures would be too dense, and drawing the frame would
 * fail, too, because the key type would not fit in anymore.
 */
#define	FLDBASE		8
#define	FLDSIZE_Y	(FLDBASE + 1)
#define	FLDSIZE_X	(FLDBASE * 2 + 1)
static char *
fingerprint_randomart(u_char *dgst_raw, size_t dgst_raw_len,
    const struct sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	char	*augmentation_string = " .o+=*BOX@%&#/^SE";
	char	*retval, *p;
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i;
	u_int	 b;
	int	 x, y;
	size_t	 len = strlen(augmentation_string) - 1;

	if ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == NULL)
		return NULL;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * sizeof(char));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	for (i = 0; i < dgst_raw_len; i++) {
		int input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		for (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAX(x, 0);
			y = MAX(y, 0);
			x = MIN(x, FLDSIZE_X - 1);
			y = MIN(y, FLDSIZE_Y - 1);

			/* augment the field */
			if (field[x][y] < len - 2)
				field[x][y]++;
			input = input >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* fill in retval */
	snprintf(retval, FLDSIZE_X, "+--[%4s %4u]",
	    sshkey_type(k), sshkey_size(k));
	p = strchr(retval, '\0');

	/* output upper border */
	for (i = p - retval - 1; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	for (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		for (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MIN(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	for (i = 0; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	return retval;
}

char *
sshkey_fingerprint(const struct sshkey *k, enum sshkey_fp_type dgst_type,
    enum sshkey_fp_rep dgst_rep)
{
	char *retval = NULL;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	if ((dgst_raw = sshkey_fingerprint_raw(k, dgst_type,
	    &dgst_raw_len)) == NULL)
		return NULL;
	switch (dgst_rep) {
	case SSH_FP_HEX:
		retval = fingerprint_hex(dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_RANDOMART:
		retval = fingerprint_randomart(dgst_raw, dgst_raw_len, k);
		break;
	default:
		bzero(dgst_raw, dgst_raw_len);
		free(dgst_raw);
		return NULL;
	}
	bzero(dgst_raw, dgst_raw_len);
	free(dgst_raw);
	return retval;
}

/*
 * Reads a multiple-precision integer in decimal from the buffer, and advances
 * the pointer.  The integer must already be initialized.  This function is
 * permitted to modify the buffer.  This leaves *cpp to point just beyond the
 * last processed character.
 */
static int
read_decimal_bignum(char **cpp, BIGNUM *v)
{
	char *cp;
	size_t e;
	int skip = 1;	/* skip white space */

	cp = *cpp;
	while (*cp == ' ' || *cp == '\t')
		cp++;
	e = strspn(cp, "0123456789");
	if (e == 0)
		return SSH_ERR_INVALID_FORMAT;
	if (e > SSHBUF_MAX_BIGNUM * 3)
		return SSH_ERR_BIGNUM_TOO_LARGE;
	if (cp[e] == '\0')
		skip = 0;
	else if (index(" \t\r\n", cp[e]) == NULL)
		return SSH_ERR_INVALID_FORMAT;
	cp[e] = '\0';
	if (BN_dec2bn(&v, cp) <= 0)
		return SSH_ERR_INVALID_FORMAT;
	*cpp = cp + e + skip;
	return 0;
}

/* returns 0 ok, and < 0 error */
int
sshkey_read(struct sshkey *ret, char **cpp)
{
	struct sshkey *k;
	int retval = SSH_ERR_INVALID_FORMAT;
	char *cp, *ep, *space;
	int r, type, curve_nid = -1;
	u_long bits;
	struct sshbuf *blob;

	cp = *cpp;

	switch (ret->type) {
	case KEY_RSA1:
		/* Get number of bits. */
		bits = strtoul(cp, &ep, 10);
		if (*cp == '\0' || index(" \t\r\n", *ep) == NULL ||
		    bits == 0 || bits > SSHBUF_MAX_BIGNUM * 8)
			return SSH_ERR_INVALID_FORMAT;	/* Bad bit count... */
		/* Get public exponent, public modulus. */
		if ((r = read_decimal_bignum(&ep, ret->rsa->e)) < 0)
			return r;
		if ((r = read_decimal_bignum(&ep, ret->rsa->n)) < 0)
			return r;
		*cpp = ep;
		/* validate the claimed number of bits */
		if (BN_num_bits(ret->rsa->n) != (int)bits)
			return SSH_ERR_KEY_BITS_MISMATCH;
		retval = 0;
		break;
	case KEY_UNSPEC:
	case KEY_RSA:
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_DSA_CERT_V00:
	case KEY_RSA_CERT_V00:
	case KEY_DSA_CERT:
	case KEY_ECDSA_CERT:
	case KEY_RSA_CERT:
		space = strchr(cp, ' ');
		if (space == NULL)
			return SSH_ERR_INVALID_FORMAT;
		*space = '\0';
		type = sshkey_type_from_name(cp);
		if (sshkey_type_plain(type) == KEY_ECDSA &&
		    (curve_nid = sshkey_ecdsa_nid_from_name(cp)) == -1)
			return SSH_ERR_EC_CURVE_INVALID;
		*space = ' ';
		if (type == KEY_UNSPEC)
			return SSH_ERR_INVALID_FORMAT;
		cp = space+1;
		if (*cp == '\0')
			return SSH_ERR_INVALID_FORMAT;
		if (ret->type == KEY_UNSPEC) {
			ret->type = type;
		} else if (ret->type != type)
			return SSH_ERR_KEY_TYPE_MISMATCH;
		if ((blob = sshbuf_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		/* trim comment */
		space = strchr(cp, ' ');
		if (space) 
			*space = '\0';
		if ((r = sshbuf_b64tod(blob, cp)) != 0) {
			sshbuf_free(blob);
			return r;
		}
		if ((r = sshkey_from_blob(sshbuf_ptr(blob),
		    sshbuf_len(blob), &k)) != 0) {
			sshbuf_free(blob);
			return r;
		}
		sshbuf_free(blob);
		if (k->type != type) {
			sshkey_free(k);
			return SSH_ERR_KEY_TYPE_MISMATCH;
		}
		if (sshkey_type_plain(type) == KEY_ECDSA &&
		    curve_nid != k->ecdsa_nid) {
			sshkey_free(k);
			return SSH_ERR_EC_CURVE_MISMATCH;
		}
/*XXXX*/
		if (sshkey_is_cert(ret)) {
			if (!sshkey_is_cert(k)) {
				sshkey_free(k);
				return SSH_ERR_EXPECTED_CERT;
			}
			if (ret->cert != NULL)
				cert_free(ret->cert);
			ret->cert = k->cert;
			k->cert = NULL;
		}
		if (sshkey_type_plain(ret->type) == KEY_RSA) {
			if (ret->rsa != NULL)
				RSA_free(ret->rsa);
			ret->rsa = k->rsa;
			k->rsa = NULL;
#ifdef DEBUG_PK
			RSA_print_fp(stderr, ret->rsa, 8);
#endif
		}
		if (sshkey_type_plain(ret->type) == KEY_DSA) {
			if (ret->dsa != NULL)
				DSA_free(ret->dsa);
			ret->dsa = k->dsa;
			k->dsa = NULL;
#ifdef DEBUG_PK
			DSA_print_fp(stderr, ret->dsa, 8);
#endif
		}
		if (sshkey_type_plain(ret->type) == KEY_ECDSA) {
			if (ret->ecdsa != NULL)
				EC_KEY_free(ret->ecdsa);
			ret->ecdsa = k->ecdsa;
			ret->ecdsa_nid = k->ecdsa_nid;
			k->ecdsa = NULL;
			k->ecdsa_nid = -1;
#ifdef DEBUG_PK
			sshkey_dump_ec_key(ret->ecdsa);
#endif
		}
		retval = 0;
/*XXXX*/
		sshkey_free(k);
		if (retval != 0)
			break;
		/* advance cp: skip whitespace and data */
		while (*cp == ' ' || *cp == '\t')
			cp++;
		while (*cp != '\0' && *cp != ' ' && *cp != '\t')
			cp++;
		*cpp = cp;
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	return retval;
}

int
sshkey_write(const struct sshkey *key, FILE *f)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	u_int bits = 0;
	struct sshbuf *b = NULL, *bb = NULL;
	char *uu = NULL, *dec_e = NULL, *dec_n = NULL;

	if (sshkey_is_cert(key)) {
		if (key->cert == NULL)
			return SSH_ERR_EXPECTED_CERT;
		if (sshbuf_len(key->cert->certblob) == 0)
			return SSH_ERR_KEY_LACKS_CERTBLOB;
	}
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	switch (key->type) {
	case KEY_RSA1:
		if (key->rsa == NULL || key->rsa->e == NULL ||
		    key->rsa->n == NULL) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if ((dec_e = BN_bn2dec(key->rsa->e)) == NULL ||
		    (dec_n = BN_bn2dec(key->rsa->n)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		/* size of modulus 'n' */
		if ((bits = BN_num_bits(key->rsa->n)) <= 0) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if ((ret = sshbuf_putf(b, "%u %s %s", bits, dec_e, dec_n)) != 0)
			goto out;
		break;
	case KEY_DSA:
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
	case KEY_RSA:
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		if ((bb = sshbuf_new()) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((ret = sshkey_to_blob_buf(key, bb)) != 0)
			goto out;
		if ((uu = sshbuf_dtob64(bb)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((ret = sshbuf_putf(b, "%s ", sshkey_ssh_name(key))) != 0)
			goto out;
		if ((ret = sshbuf_put(b, uu, strlen(uu))) != 0)
			goto out;
		break;
	default:
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}
	if (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		if (feof(f))
			errno = EPIPE;
		ret = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	ret = 0;
 out:
	if (b != NULL)
		sshbuf_free(b);
	if (bb != NULL)
		sshbuf_free(bb);
	if (uu != NULL)
		free(uu);
	if (dec_e != NULL)
		OPENSSL_free(dec_e);
	if (dec_n != NULL)
		OPENSSL_free(dec_n);
	return ret;
}

const char *
sshkey_cert_type(const struct sshkey *k)
{
	switch (k->cert->type) {
	case SSH2_CERT_TYPE_USER:
		return "user";
	case SSH2_CERT_TYPE_HOST:
		return "host";
	default:
		return "unknown";
	}
}

static int
rsa_generate_private_key(u_int bits, RSA **rsap)
{
	RSA *private = NULL;
	BIGNUM *f4 = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (rsap == NULL ||
	    bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((private = RSA_new()) == NULL || (f4 = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!BN_set_word(f4, RSA_F4) ||
	    !RSA_generate_key_ex(private, bits, f4, NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	*rsap = private;
	private = NULL;
	ret = 0;
 out:
	if (private != NULL)
		RSA_free(private);
	if (f4 != NULL)
		BN_free(f4);
	return ret;
}

static int
dsa_generate_private_key(u_int bits, DSA **dsap)
{
	DSA *private = DSA_new();
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (dsap == NULL || bits != 1024)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((private = DSA_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!DSA_generate_parameters_ex(private, bits, NULL, 0, NULL,
	    NULL, NULL) || !DSA_generate_key(private)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	*dsap = private;
	private = NULL;
	ret = 0;
 out:
	if (private != NULL)
		DSA_free(private);
	return ret;
}

int
sshkey_ecdsa_bits_to_nid(int bits)
{
	switch (bits) {
	case 256:
		return NID_X9_62_prime256v1;
	case 384:
		return NID_secp384r1;
	case 521:
		return NID_secp521r1;
	default:
		return -1;
	}
}

int
sshkey_ecdsa_key_to_nid(EC_KEY *k)
{
	EC_GROUP *eg;
	int nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	int nid;
	u_int i;
	BN_CTX *bnctx;
	const EC_GROUP *g = EC_KEY_get0_group(k);

	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	if ((nid = EC_GROUP_get_curve_name(g)) > 0)
		return nid;
	if ((bnctx = BN_CTX_new()) == NULL)
		return -1;
	for (i = 0; nids[i] != -1; i++) {
		if ((eg = EC_GROUP_new_by_curve_name(nids[i])) == NULL) {
			BN_CTX_free(bnctx);
			return -1;
		}
		if (EC_GROUP_cmp(g, eg, bnctx) == 0)
			break;
		EC_GROUP_free(eg);
	}
	BN_CTX_free(bnctx);
	if (nids[i] != -1) {
		/* Use the group with the NID attached */
		EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
		if (EC_KEY_set_group(k, eg) != 1) {
			EC_GROUP_free(eg);
			return -1;
		}
	}
	return nids[i];
}

static int
ecdsa_generate_private_key(u_int bits, int *nid, EC_KEY **ecdsap)
{
	EC_KEY *private;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (nid == NULL || ecdsap == NULL ||
	    (*nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((private = EC_KEY_new_by_curve_name(*nid)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_KEY_generate_key(private) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EC_KEY_set_asn1_flag(private, OPENSSL_EC_NAMED_CURVE);
	*ecdsap = private;
	private = NULL;
	ret = 0;
 out:
	if (private != NULL)
		EC_KEY_free(private);
	return ret;
}

int
sshkey_generate(int type, u_int bits, struct sshkey **keyp)
{
	struct sshkey *k;
	int ret;

	if (keyp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	*keyp = NULL;
	if ((k = sshkey_new(KEY_UNSPEC)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	switch (type) {
	case KEY_DSA:
		ret = dsa_generate_private_key(bits, &k->dsa);
		break;
	case KEY_ECDSA:
		ret = ecdsa_generate_private_key(bits, &k->ecdsa_nid,
		    &k->ecdsa);
		break;
	case KEY_RSA:
	case KEY_RSA1:
		ret = rsa_generate_private_key(bits, &k->rsa);
		break;
	case KEY_RSA_CERT_V00:
	case KEY_DSA_CERT_V00:
	case KEY_RSA_CERT:
	case KEY_DSA_CERT:
	default:
		ret = SSH_ERR_INVALID_ARGUMENT;
	}
	if (ret == 0) {
		k->type = type;
		*keyp = k;
	} else
		sshkey_free(k);
	return ret;
}

int
sshkey_cert_copy(const struct sshkey *from_key, struct sshkey *to_key)
{
	u_int i;
	const struct sshkey_cert *from;
	struct sshkey_cert *to;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (to_key->cert != NULL) {
		cert_free(to_key->cert);
		to_key->cert = NULL;
	}

	if ((from = from_key->cert) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((to = to_key->cert = cert_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((ret = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (ret = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (ret = sshbuf_putb(to->extensions, from->extensions) != 0))
		return ret;

	to->serial = from->serial;
	to->type = from->type;
	if (from->key_id == NULL)
		to->key_id = NULL;
	else if ((to->key_id = strdup(from->key_id)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	if (from->signature_key == NULL)
		to->signature_key = NULL;
	else if ((ret = sshkey_from_private(from->signature_key,
	    &to->signature_key)) != 0)
		return ret;

	if (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS)
		return SSH_ERR_INVALID_ARGUMENT;
	if (from->nprincipals > 0) {
		if ((to->principals = calloc(from->nprincipals,
		    sizeof(*to->principals))) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		for (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			if (to->principals[i] == NULL) {
				to->nprincipals = i;
				return SSH_ERR_ALLOC_FAIL;
			}
		}
	}
	to->nprincipals = from->nprincipals;
	return 0;
}

int
sshkey_from_private(const struct sshkey *k, struct sshkey **pkp)
{
	struct sshkey *n = NULL;
	int ret;

	switch (k->type) {
	case KEY_DSA:
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		if ((n = sshkey_new(k->type)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((BN_copy(n->dsa->p, k->dsa->p) == NULL) ||
		    (BN_copy(n->dsa->q, k->dsa->q) == NULL) ||
		    (BN_copy(n->dsa->g, k->dsa->g) == NULL) ||
		    (BN_copy(n->dsa->pub_key, k->dsa->pub_key) == NULL)) {
			sshkey_free(n);
			return SSH_ERR_ALLOC_FAIL;
		}
		break;
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
		if ((n = sshkey_new(k->type)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		n->ecdsa_nid = k->ecdsa_nid;
		n->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
		if (n->ecdsa == NULL) {
			sshkey_free(n);
			return SSH_ERR_ALLOC_FAIL;
		}
		if (EC_KEY_set_public_key(n->ecdsa,
		    EC_KEY_get0_public_key(k->ecdsa)) != 1) {
			sshkey_free(n);
			return SSH_ERR_LIBCRYPTO_ERROR;
		}
		break;
	case KEY_RSA:
	case KEY_RSA1:
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		if ((n = sshkey_new(k->type)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((BN_copy(n->rsa->n, k->rsa->n) == NULL) ||
		    (BN_copy(n->rsa->e, k->rsa->e) == NULL)) {
			sshkey_free(n);
			return SSH_ERR_ALLOC_FAIL;
		}
		break;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
	if (sshkey_is_cert(k)) {
		if ((ret = sshkey_cert_copy(k, n)) != 0) {
			sshkey_free(n);
			return ret;
		}
	}
	*pkp = n;
	return 0;
}

int
sshkey_names_valid2(const char *names)
{
	char *s, *cp, *p;

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	if ((s = cp = strdup(names)) == NULL)
		return 0;
	for ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		switch (sshkey_type_from_name(p)) {
		case KEY_RSA1:
		case KEY_UNSPEC:
			free(s);
			return 0;
		}
	}
	free(s);
	return 1;
}

static int
cert_parse(struct sshbuf *b, struct sshkey *key, const u_char *blob,
    size_t blen)
{
	u_char *principals = NULL, *critical = NULL, *exts = NULL;
	u_char *sig_key = NULL, *sig = NULL;
	size_t signed_len, plen, clen, sklen, slen, kidlen, elen;
	struct sshbuf *tmp;
	char *principal;
	int ret;
	int v00 = key->type == KEY_DSA_CERT_V00 ||
	    key->type == KEY_RSA_CERT_V00;
	char **oprincipals;

	if ((tmp = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* Copy the entire key blob for verification and later serialisation */
	if ((ret = sshbuf_put(key->cert->certblob, blob, blen)) != 0)
		return ret;

	elen = 0; /* Not touched for v00 certs */
	principals = exts = critical = sig_key = sig = NULL;
	if ((!v00 && (ret = sshbuf_get_u64(b, &key->cert->serial)) != 0) ||
	    (ret = sshbuf_get_u32(b, &key->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &key->cert->key_id, &kidlen)) != 0 ||
	    (ret = sshbuf_get_string(b, &principals, &plen)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_before)) != 0 ||
	    (ret = sshbuf_get_string(b, &critical, &clen)) != 0 ||
	    (!v00 && (ret = sshbuf_get_string(b, &exts, &elen)) != 0) ||
	    (v00 && (ret = sshbuf_get_string_direct(b, NULL, NULL)) != 0) ||
	    (ret = sshbuf_get_string_direct(b, NULL, NULL)) != 0 ||
	    (ret = sshbuf_get_string(b, &sig_key, &sklen)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(key->cert->certblob) - sshbuf_len(b);

	if ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if (key->cert->type != SSH2_CERT_TYPE_USER &&
	    key->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_KEY_CERT_UNKNOWN_TYPE;
		goto out;
	}

	if ((ret = sshbuf_put(tmp, principals, plen)) != 0)
		goto out;
	while (sshbuf_len(tmp) > 0) {
		if (key->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((ret = sshbuf_get_cstring(tmp, &principal, &plen)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		oprincipals = key->cert->principals;
		key->cert->principals = realloc(key->cert->principals,
		    (key->cert->nprincipals + 1) * 
		    sizeof(*key->cert->principals));
		if (key->cert->principals == NULL) {
			free(principal);
			key->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		key->cert->principals[key->cert->nprincipals++] = principal;
	}

	sshbuf_reset(tmp);

	if ((ret = sshbuf_put(key->cert->critical, critical, clen)) != 0 ||
	    (ret = sshbuf_put(tmp, critical, clen)) != 0)
		goto out;

	/* validate structure */
	while (sshbuf_len(tmp) != 0) {
		if ((ret = sshbuf_get_string_direct(tmp, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(tmp, NULL, NULL)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	sshbuf_reset(tmp);

	if ((ret = sshbuf_put(key->cert->extensions, exts, elen)) != 0 ||
	    (ret = sshbuf_put(tmp, exts, elen)) != 0)
		goto out;

	/* validate structure */
	while (sshbuf_len(tmp) != 0) {
		if ((ret = sshbuf_get_string_direct(tmp, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(tmp, NULL, NULL)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	sshbuf_reset(tmp);

	if (sshkey_from_blob(sig_key, sklen, &key->cert->signature_key) != 0) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	if (key->cert->signature_key->type != KEY_RSA &&
	    key->cert->signature_key->type != KEY_DSA &&
	    key->cert->signature_key->type != KEY_ECDSA) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}

	if ((ret = sshkey_verify(key->cert->signature_key, sig, slen, 
	    sshbuf_ptr(key->cert->certblob), signed_len, 0)) != 0)
		goto out;
	ret = 0;

 out:
	sshbuf_free(tmp);
	free(principals);
	free(critical);
	free(exts);
	free(sig_key);
	free(sig);
	return ret;
}

int
sshkey_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp)
{
	struct sshbuf *b;
	int type, nid = -1, ret = SSH_ERR_INTERNAL_ERROR;
	char *ktype = NULL, *curve = NULL;
	struct sshkey *key = NULL;
	EC_POINT *q = NULL;

#ifdef DEBUG_PK /* XXX */
	dump_base64(stderr, blob, blen);
#endif
	*keyp = NULL;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((ret = sshbuf_put(b, blob, blen)) != 0)
		goto out;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	type = sshkey_type_from_name(ktype);
	if (sshkey_type_plain(type) == KEY_ECDSA)
		nid = sshkey_ecdsa_nid_from_name(ktype);

	switch (type) {
	case KEY_RSA_CERT:
		if (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		/* FALLTHROUGH */
	case KEY_RSA:
	case KEY_RSA_CERT_V00:
		key = sshkey_new(type);
		if (sshbuf_get_bignum2(b, key->rsa->e) == -1 ||
		    sshbuf_get_bignum2(b, key->rsa->n) == -1) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
#ifdef DEBUG_PK
		RSA_print_fp(stderr, key->rsa, 8);
#endif
		break;
	case KEY_DSA_CERT:
		if (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		/* FALLTHROUGH */
	case KEY_DSA:
	case KEY_DSA_CERT_V00:
		key = sshkey_new(type);
		if (sshbuf_get_bignum2(b, key->dsa->p) == -1 ||
		    sshbuf_get_bignum2(b, key->dsa->q) == -1 ||
		    sshbuf_get_bignum2(b, key->dsa->g) == -1 ||
		    sshbuf_get_bignum2(b, key->dsa->pub_key) == -1) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
#ifdef DEBUG_PK
		DSA_print_fp(stderr, key->dsa, 8);
#endif
		break;
	case KEY_ECDSA_CERT:
		if (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		/* FALLTHROUGH */
	case KEY_ECDSA:
		key = sshkey_new(type);
		key->ecdsa_nid = nid;
		if (sshbuf_get_cstring(b, &curve, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
			ret = SSH_ERR_EC_CURVE_MISMATCH;
			goto out;
		}
		if (key->ecdsa != NULL)
			EC_KEY_free(key->ecdsa);
		if ((key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid))
		    == NULL) {
			ret = SSH_ERR_EC_CURVE_INVALID;
			goto out;
		}
		if ((q = EC_POINT_new(EC_KEY_get0_group(key->ecdsa))) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if (sshbuf_get_ec(b, q, EC_KEY_get0_group(key->ecdsa)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if (sshkey_ec_validate_public(EC_KEY_get0_group(key->ecdsa),
		    q) != 0) {
			ret = SSH_ERR_KEY_INVALID_EC_VALUE;
			goto out;
		}
		if (EC_KEY_set_public_key(key->ecdsa, q) != 1) {
			/* XXX assume it is a allocation error */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
#ifdef DEBUG_PK
		sshkey_dump_ec_point(EC_KEY_get0_group(key->ecdsa), q);
#endif
		break;
	case KEY_UNSPEC:
		key = sshkey_new(type);
		break;
	default:
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}

	/* Parse certificate potion */
	if (sshkey_is_cert(key) &&
	   (ret = cert_parse(b, key, blob, blen)) != 0)
		goto out;

	if (key != NULL && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ret = 0;
	*keyp = key;
 out:
	if (ret != 0 && key != NULL)
		sshkey_free(key);
	free(ktype);
	free(curve);
	if (q != NULL)
		EC_POINT_free(q);
	sshbuf_free(b);
	return ret;
}

int
sshkey_sign(const struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	if (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
	switch (key->type) {
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
	case KEY_DSA:
		return ssh_dss_sign(key, sigp, lenp, data, datalen, compat);
	case KEY_ECDSA_CERT:
	case KEY_ECDSA:
		return ssh_ecdsa_sign(key, sigp, lenp, data, datalen, compat);
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
	case KEY_RSA:
		return ssh_rsa_sign(key, sigp, lenp, data, datalen, compat);
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
}

/*
 * ssh_key_verify returns 0 for a correct signature  and < 0 on error.
 */
int
sshkey_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, u_int compat)
{
	if (siglen == 0)
		return -1;

	if (dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
	switch (key->type) {
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
	case KEY_DSA:
		return ssh_dss_verify(key, sig, siglen, data, dlen, compat);
	case KEY_ECDSA_CERT:
	case KEY_ECDSA:
		return ssh_ecdsa_verify(key, sig, siglen, data, dlen, compat);
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
	case KEY_RSA:
		return ssh_rsa_verify(key, sig, siglen, data, dlen, compat);
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
}

/* Converts a private to a public key */
int
sshkey_demote(const struct sshkey *k, struct sshkey **dkp)
{
	struct sshkey *pk;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if ((pk = calloc(1, sizeof(*pk))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	pk->type = k->type;
	pk->flags = k->flags;
	pk->ecdsa_nid = k->ecdsa_nid;
	pk->dsa = NULL;
	pk->ecdsa = NULL;
	pk->rsa = NULL;

	switch (k->type) {
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		if ((ret = sshkey_cert_copy(k, pk)) != 0)
			goto fail;
		/* FALLTHROUGH */
	case KEY_RSA1:
	case KEY_RSA:
		if ((pk->rsa = RSA_new()) == NULL ||
		    (pk->rsa->e = BN_dup(k->rsa->e)) == NULL ||
		    (pk->rsa->n = BN_dup(k->rsa->n)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto fail;
			}
		break;
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		if ((ret = sshkey_cert_copy(k, pk)) != 0)
			goto fail;
		/* FALLTHROUGH */
	case KEY_DSA:
		if ((pk->dsa = DSA_new()) == NULL ||
		    (pk->dsa->p = BN_dup(k->dsa->p)) == NULL ||
		    (pk->dsa->q = BN_dup(k->dsa->q)) == NULL ||
		    (pk->dsa->g = BN_dup(k->dsa->g)) == NULL ||
		    (pk->dsa->pub_key = BN_dup(k->dsa->pub_key)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		break;
	case KEY_ECDSA_CERT:
		if ((ret = sshkey_cert_copy(k, pk)) != 0)
			goto fail;
		/* FALLTHROUGH */
	case KEY_ECDSA:
		pk->ecdsa = EC_KEY_new_by_curve_name(pk->ecdsa_nid);
		if (pk->ecdsa == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		if (EC_KEY_set_public_key(pk->ecdsa,
		    EC_KEY_get0_public_key(k->ecdsa)) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto fail;
		}
		break;
	default:
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
 fail:
		sshkey_free(pk);
		return ret;
	}
	*dkp = pk;
	return 0;
}

int
sshkey_is_cert(const struct sshkey *k)
{
	if (k == NULL)
		return 0;
	switch (k->type) {
	case KEY_RSA_CERT_V00:
	case KEY_DSA_CERT_V00:
	case KEY_RSA_CERT:
	case KEY_DSA_CERT:
	case KEY_ECDSA_CERT:
		return 1;
	default:
		return 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
int
sshkey_type_plain(int type)
{
	switch (type) {
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		return KEY_RSA;
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		return KEY_DSA;
	case KEY_ECDSA_CERT:
		return KEY_ECDSA;
	default:
		return type;
	}
}

/* Convert a KEY_RSA or KEY_DSA to their _CERT equivalent */
int
sshkey_to_certified(struct sshkey *k, int legacy)
{
	switch (k->type) {
	case KEY_RSA:
		if ((k->cert = cert_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		k->type = legacy ? KEY_RSA_CERT_V00 : KEY_RSA_CERT;
		return 0;
	case KEY_DSA:
		if ((k->cert = cert_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		k->type = legacy ? KEY_DSA_CERT_V00 : KEY_DSA_CERT;
		return 0;
	case KEY_ECDSA:
		if (legacy)
			return SSH_ERR_INVALID_ARGUMENT;
		if ((k->cert = cert_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		k->type = KEY_ECDSA_CERT;
		return 0;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
}

/* Convert a KEY_RSA_CERT or KEY_DSA_CERT to their raw key equivalent */
int
sshkey_drop_cert(struct sshkey *k)
{
	switch (k->type) {
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		cert_free(k->cert);
		k->type = KEY_RSA;
		return 0;
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		cert_free(k->cert);
		k->type = KEY_DSA;
		return 0;
	case KEY_ECDSA_CERT:
		cert_free(k->cert);
		k->type = KEY_ECDSA;
		return 0;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
}

/*
 * Sign a KEY_RSA_CERT, KEY_DSA_CERT or KEY_ECDSA_CERT, (re-)generating
 * the signed certblob
 */
int
sshkey_certify(struct sshkey *k, struct sshkey *ca)
{
	struct sshbuf *principals = NULL;
	u_char *ca_blob = NULL, *sig_blob = NULL, nonce[32];
	size_t i, ca_len, sig_len;
	int ret;
	struct sshbuf *cert;

	if (k == NULL || k->cert == NULL || k->cert->certblob == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_is_cert(k))
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if (ca->type != KEY_RSA && ca->type != KEY_DSA &&
	    ca->type != KEY_ECDSA)
		return SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	if ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		return SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	if ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		goto out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, sizeof(nonce));
	if (!sshkey_cert_is_legacy(k)) {
		if ((ret = sshbuf_put_string(cert, nonce, sizeof(nonce))) != 0)
			goto out;
	}

	switch (k->type) {
	case KEY_DSA_CERT_V00:
	case KEY_DSA_CERT:
		if ((ret = sshbuf_put_bignum2(cert, k->dsa->p)) != 0 ||
		    (ret = sshbuf_put_bignum2(cert, k->dsa->q)) != 0 ||
		    (ret = sshbuf_put_bignum2(cert, k->dsa->g)) != 0 ||
		    (ret = sshbuf_put_bignum2(cert, k->dsa->pub_key)) != 0)
			goto out;
		break;
	case KEY_ECDSA_CERT:
		if ((ret = sshbuf_put_cstring(cert,
		    sshkey_curve_nid_to_name(k->ecdsa_nid))) != 0 ||
		    (ret = sshbuf_put_ec(cert,
		    EC_KEY_get0_public_key(k->ecdsa),
		    EC_KEY_get0_group(k->ecdsa))) != 0)
			goto out;
		break;
	case KEY_RSA_CERT_V00:
	case KEY_RSA_CERT:
		if ((ret = sshbuf_put_bignum2(cert, k->rsa->e)) != 0 ||
		    (sshbuf_put_bignum2(cert, k->rsa->n)) != 0)
			goto out;
		break;
	default:
		ret = SSH_ERR_INVALID_ARGUMENT;
	}

	/* -v01 certs have a serial number next */
	if (!sshkey_cert_is_legacy(k)) {
		if ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0)
			goto out;
	}

	if ((ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->key_id)) != 0)
		goto out;

	if ((principals = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	for (i = 0; i < k->cert->nprincipals; i++) {
		if ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			goto out;
	}
	if ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0)
		goto out;

	/* -v01 certs have non-critical options here */
	if (!sshkey_cert_is_legacy(k)) {
		if ((ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0)
			goto out;
	}

	/* -v00 certs put the nonce at the end */
	if (sshkey_cert_is_legacy(k)) {
		if ((ret = sshbuf_put_string(cert, nonce, sizeof(nonce))) != 0)
			goto out;
	}

	if ((ret = sshbuf_put_string(cert, NULL, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		goto out;

	/* Sign the whole mess */
	if ((ret = sshkey_sign(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), 0)) != 0)
		goto out;

	/* Append signature and we are done */
	if ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		goto out;
	ret = 0;
 out:
	if (ret != 0)
		sshbuf_reset(cert);
	if (sig_blob != NULL)
		free(sig_blob);
	if (ca_blob != NULL)
		free(ca_blob);
	if (principals != NULL)
		sshbuf_free(principals);
	return ret;
}

int
sshkey_cert_check_authority(const struct sshkey *k,
    int want_host, int require_principal,
    const char *name, const char **reason)
{
	u_int i, principal_matches;
	time_t now = time(NULL);

	if (want_host) {
		if (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	} else {
		if (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	}
	if (now < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if ((u_int64_t)now < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if ((u_int64_t)now >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (k->cert->nprincipals == 0) {
		if (require_principal) {
			*reason = "Certificate lacks principal list";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	} else if (name != NULL) {
		principal_matches = 0;
		for (i = 0; i < k->cert->nprincipals; i++) {
			if (strcmp(name, k->cert->principals[i]) == 0) {
				principal_matches = 1;
				break;
			}
		}
		if (!principal_matches) {
			*reason = "Certificate invalid: name is not a listed "
			    "principal";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	}
	return 0;
}

int
sshkey_ec_validate_public(const EC_GROUP *group, const EC_POINT *public)
{
	BN_CTX *bnctx;
	EC_POINT *nq = NULL;
	BIGNUM *order, *x, *y, *tmp;
	int ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	if ((bnctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	BN_CTX_start(bnctx);

	/*
	 * We shouldn't ever hit this case because bignum_get_ecpoint()
	 * refuses to load GF2m points.
	 */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) !=
	    NID_X9_62_prime_field)
		goto out;

	/* Q != infinity */
	if (EC_POINT_is_at_infinity(group, public))
		goto out;

	if ((x = BN_CTX_get(bnctx)) == NULL ||
	    (y = BN_CTX_get(bnctx)) == NULL ||
	    (order = BN_CTX_get(bnctx)) == NULL ||
	    (tmp = BN_CTX_get(bnctx)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* log2(x) > log2(order)/2, log2(y) > log2(order)/2 */
	if (EC_GROUP_get_order(group, order, bnctx) != 1 ||
	    EC_POINT_get_affine_coordinates_GFp(group, public,
	    x, y, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_num_bits(x) <= BN_num_bits(order) / 2 ||
	    BN_num_bits(y) <= BN_num_bits(order) / 2)
		goto out;

	/* nQ == infinity (n == order of subgroup) */
	if ((nq = EC_POINT_new(group)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_POINT_mul(group, nq, NULL, public, order, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EC_POINT_is_at_infinity(group, nq) != 1)
		goto out;

	/* x < order - 1, y < order - 1 */
	if (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_cmp(x, tmp) >= 0 || BN_cmp(y, tmp) >= 0)
		goto out;
	ret = 0;
 out:
	BN_CTX_free(bnctx);
	if (nq != NULL)
		EC_POINT_free(nq);
	return ret;
}

int
sshkey_ec_validate_private(const EC_KEY *key)
{
	BN_CTX *bnctx;
	BIGNUM *order, *tmp;
	int ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	if ((bnctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	BN_CTX_start(bnctx);

	if ((order = BN_CTX_get(bnctx)) == NULL ||
	    (tmp = BN_CTX_get(bnctx)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* log2(private) > log2(order)/2 */
	if (EC_GROUP_get_order(EC_KEY_get0_group(key), order, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_num_bits(EC_KEY_get0_private_key(key)) <=
	    BN_num_bits(order) / 2)
		goto out;

	/* private < order - 1 */
	if (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0)
		goto out;
	ret = 0;
 out:
	BN_CTX_free(bnctx);
	return ret;
}

void
sshkey_dump_ec_point(const EC_GROUP *group, const EC_POINT *point)
{
	BIGNUM *x, *y;
	BN_CTX *bnctx;

	if (point == NULL) {
		fputs("point=(NULL)\n", stderr);
		return;
	}
	if ((bnctx = BN_CTX_new()) == NULL) {
		fprintf(stderr, "%s: BN_CTX_new failed\n", __func__);
		return;
	}
	BN_CTX_start(bnctx);
	if ((x = BN_CTX_get(bnctx)) == NULL ||
	    (y = BN_CTX_get(bnctx)) == NULL) {
		fprintf(stderr, "%s: BN_CTX_get failed\n", __func__);
		return;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) !=
	    NID_X9_62_prime_field) {
		fprintf(stderr, "%s: group is not a prime field\n", __func__);
		return;
	}
	if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y,
	    bnctx) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates_GFp\n",
		    __func__);
		return;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
	BN_CTX_free(bnctx);
}

void
sshkey_dump_ec_key(const EC_KEY *key)
{
	const BIGNUM *exponent;

	sshkey_dump_ec_point(EC_KEY_get0_group(key),
	    EC_KEY_get0_public_key(key));
	fputs("exponent=", stderr);
	if ((exponent = EC_KEY_get0_private_key(key)) == NULL)
		fputs("(NULL)", stderr);
	else
		BN_print_fp(stderr, EC_KEY_get0_private_key(key));
	fputs("\n", stderr);
}

