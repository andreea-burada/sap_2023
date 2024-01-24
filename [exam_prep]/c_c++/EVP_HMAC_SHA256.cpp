
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>


typedef unsigned char byte;
#define UNUSED(x) ((void)x)
const char hn[] = "SHA256";

/* Returns 0 for success, non-0 otherwise */
int make_keys(EVP_PKEY** signKey, EVP_PKEY** verifyKey);

/* Returns 0 for success, non-0 otherwise */
int sign_it(const byte* message, size_t messageLength, byte** signature, size_t* signatureLength, EVP_PKEY* pKey);

/* Returns 0 for success, non-0 otherwise */
int verify_it(const byte* message, size_t messageLength, const byte* signature, size_t signatureLength, EVP_PKEY* pKey);

/* Prints a buffer to stdout. Label is optional */
void print_it(const char* label, const byte* buff, size_t len);

int main(int argc, char* argv[])
{
	printf("Testing HMAC functions with EVP_DigestSign\n");

	OpenSSL_add_all_algorithms();

	/* Sign and Verify HMAC keys */
	EVP_PKEY *signKey = NULL, *verifyKey = NULL;

	int rc = make_keys(&signKey, &verifyKey);
	assert(rc == 0);
	
	if (rc != 0)
		exit(1);

	assert(signKey != NULL);
	if (signKey == NULL)
		exit(1);

	assert(verifyKey != NULL);
	if (verifyKey == NULL)
		exit(1);

	const byte message[] = "Now is the time for all good men to come to the aide of their country";
	byte* signature = NULL;
	size_t signatureLength = 0;

	/* Using the signKey or signing key */
	rc = sign_it(message, sizeof(message), &signature, &signatureLength, signKey);
	assert(rc == 0);
	if (rc == 0) {
		printf("Created signature\n");
	}
	else {
		printf("Failed to create signature, return code %d\n", rc);
		exit(1); /* Should cleanup here */
	}

	print_it("Signature", signature, signatureLength);

#if 0
	/* Tamper with signature */
	printf("Tampering with signature\n");
	signature[0] ^= 0x01;
#endif

#if 0
	/* Tamper with signature */
	printf("Tampering with signature\n");
	signature[signatureLength - 1] ^= 0x01;
#endif

	/* Using the verifyKey or verifying key */
	rc = verify_it(message, sizeof(message), signature, signatureLength, verifyKey);
	if (rc == 0) {
		printf("Verified signature\n");
	}
	else {
		printf("Failed to verify signature, return code %d\n", rc);
	}

	if (signature)
		OPENSSL_free(signature);

	if (signKey)
		EVP_PKEY_free(signKey);

	if (verifyKey)
		EVP_PKEY_free(verifyKey);

	return 0;
}

int sign_it(const byte* message, size_t messageLength, byte** signature, size_t* signatureLength, EVP_PKEY* pKey)
{
	/* Returned to caller */
	int result = -1;

	if (!message || !messageLength || !signature || !pKey) {
		assert(0);
		return -1;
	}

	if (*signature)
		OPENSSL_free(*signature);

	*signature = NULL;
	*signatureLength = 0;

	EVP_MD_CTX* context = NULL;

	do
	{
		context = EVP_MD_CTX_create();
		assert(context != NULL);
		if (context == NULL) {
			printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		const EVP_MD* messageDigest = EVP_get_digestbyname(hn);
		assert(messageDigest != NULL);
		if (messageDigest == NULL) {
			printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		int rc = EVP_DigestInit_ex(context, messageDigest, NULL);
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		rc = EVP_DigestSignInit(context, NULL, messageDigest, NULL, pKey);
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		rc = EVP_DigestSignUpdate(context, message, messageLength);
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		size_t req = 0;
		rc = EVP_DigestSignFinal(context, NULL, &req); // only the length of the signature is returned by req
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		assert(req > 0);
		if (!(req > 0)) {
			printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		*signature = (byte*)OPENSSL_malloc(req);
		assert(*signature != NULL);
		if (*signature == NULL) {
			printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		*signatureLength = req;
		rc = EVP_DigestSignFinal(context, *signature, signatureLength); // the signature buffer is populated by the signature content (bytes)
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
			break; /* failed */
		}

		assert(req == *signatureLength);
		if (rc != 1) {
			printf("EVP_DigestSignFinal failed, mismatched signature sizes %zd, %zd", req, *signatureLength);
			break; /* failed */
		}

		result = 0;

	} while (0);

	if (context) {
		EVP_MD_CTX_destroy(context);
		context = NULL;
	}

	/* Convert to 0/1 result */
	return !!result;
}

int verify_it(const byte* message, size_t messageLength, const byte* signature, size_t signatureLength, EVP_PKEY* pKey)
{
	/* Returned to caller */
	int result = -1;

	if (!message || !messageLength || !signature || !signatureLength || !pKey) {
		assert(0);
		return -1;
	}

	EVP_MD_CTX* context = NULL;

	do
	{
		context = EVP_MD_CTX_create();
		assert(context != NULL);
		if (context == NULL) {
			printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		const EVP_MD* messageDigest = EVP_get_digestbyname(hn);
		assert(messageDigest != NULL);
		if (messageDigest == NULL) {
			printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		int rc = EVP_DigestInit_ex(context, messageDigest, NULL);
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		rc = EVP_DigestSignInit(context, NULL, messageDigest, NULL, pKey);
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		rc = EVP_DigestSignUpdate(context, message, messageLength);
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		byte buff[EVP_MAX_MD_SIZE];
		size_t size = sizeof(buff);

		rc = EVP_DigestSignFinal(context, buff, &size);
		assert(rc == 1);
		if (rc != 1) {
			printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		assert(size > 0);
		if (!(size > 0)) {
			printf("EVP_DigestSignFinal failed (2)\n");
			break; /* failed */
		}

		const size_t m = (signatureLength < size ? signatureLength : size);
		result = !!CRYPTO_memcmp(signature, buff, m);

		OPENSSL_cleanse(buff, sizeof(buff));

	} while (0);

	if (context) {
		EVP_MD_CTX_destroy(context);
		context = NULL;
	}

	/* Convert to 0/1 result */
	return !!result;
}

void print_it(const char* label, const byte* buff, size_t len)
{
	if (!buff || !len)
		return;

	if (label)
		printf("%s: ", label);

	for (size_t i = 0; i < len; ++i)
		printf("%02X", buff[i]);

	printf("\n");
}

/* Create an HMAC key */
int make_keys(EVP_PKEY** signKey, EVP_PKEY** verifyKey)
{
	/* HMAC key */
	byte hmacKey[EVP_MAX_MD_SIZE];

	int result = -1;

	if (!signKey || !verifyKey)
		return -1;

	if (*signKey != NULL) {
		EVP_PKEY_free(*signKey);
		*signKey = NULL;
	}

	if (*verifyKey != NULL) {
		EVP_PKEY_free(*verifyKey);
		*verifyKey = NULL;
	}

	do
	{
		const EVP_MD* messageDigest = EVP_get_digestbyname(hn); // initialize the MD structure accroding to the message digest algo name
		assert(messageDigest != NULL);
		if (messageDigest == NULL) {
			printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		int size = EVP_MD_size(messageDigest);
		assert(size >= 16);
		if (!(size >= 16)) {
			printf("EVP_MD_size failed, error 0x%lx\n", ERR_get_error());
			break; /* failed */
		}

		assert(size <= sizeof(hmacKey));
		if (!(size <= sizeof(hmacKey))) {
			printf("EVP_MD_size is too large\n");
			break; /* failed */
		}

		/* Generate bytes */
		int rc = RAND_bytes(hmacKey, size);
		assert(rc == 1);
		if (rc != 1) {
			printf("RAND_bytes failed, error 0x%lx\n", ERR_get_error());
			break;
		}

		print_it("HMAC key", hmacKey, size);

		*signKey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hmacKey, size);
		assert(*signKey != NULL);
		if (*signKey == NULL) {
			printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
			break;
		}

		*verifyKey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hmacKey, size);
		assert(*verifyKey != NULL);
		if (*verifyKey == NULL) {
			printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
			break;
		}

		result = 0;

	} while (0);

	OPENSSL_cleanse(hmacKey, sizeof(hmacKey));

	/* Convert to 0/1 result */
	return !!result;
}
