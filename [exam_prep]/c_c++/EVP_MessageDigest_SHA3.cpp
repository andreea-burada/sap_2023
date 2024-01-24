#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, messageDigestContext) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(messageDigestContext); exit(EXIT_FAILURE); }

int main(int argc, char* const argv[])
{
	unsigned char buffer[] = { 0x2b, 0xbb, 0x42, 0xb9, 0x20, 0xb7, 0xfe, 0xb4,
							   0xe3, 0x96, 0x2a, 0x15, 0x52, 0xcc, 0x39, 0x0f };

	EVP_MD_CTX* messageDigestContext;
	unsigned char* digest;
	unsigned int digestLength;
	unsigned int digestBlockSize;
	EVP_MD* algorithm = NULL;

	//algorithm = (EVP_MD*)EVP_sha3_224();
	//algorithm = (EVP_MD*)EVP_sha3_256();
	//algorithm = (EVP_MD*)EVP_sha3_384();
	algorithm = (EVP_MD*)EVP_sha3_512();

	if ((messageDigestContext = EVP_MD_CTX_create()) == NULL) {
		HANDLE_ERROR("EVP_MD_CTX_create() error")
	}

	// initialize digest engine
	// returns 1 if successful
	if (EVP_DigestInit_ex(messageDigestContext, algorithm, NULL) != 1) { 
		HANDLE_ERROR2("EVP_DigestInit_ex() error", messageDigestContext)
	}

	// returns 1 if successful
	if (EVP_DigestUpdate(messageDigestContext, buffer, sizeof(buffer)) != 1) { 
	// returns 1 if successful; NIST test vector with empty input
	//if (EVP_DigestUpdate(messageDigestContext, NULL, 0) != 1) { 
		HANDLE_ERROR2("EVP_DigestUpdate() error", messageDigestContext)
	}

	digestLength = EVP_MD_size(algorithm);
	digestBlockSize = EVP_MD_block_size(algorithm);

	// OPENSSL_malloc for cross-platform development
	if ((digest = (unsigned char*)OPENSSL_malloc(digestLength)) == NULL) { 
		HANDLE_ERROR2("OPENSSL_malloc() error", messageDigestContext)
	}

	// produce digest
	unsigned int sha3_length = 0;
	// returns 1 if successful; sha3_length MUST be equal to digestLength
	if (EVP_DigestFinal_ex(messageDigestContext, digest, &sha3_length) != 1) { 
		// OPENSSL_free for cross-platform development
		OPENSSL_free(digest); 
		HANDLE_ERROR2("EVP_DigestFinal_ex() error", messageDigestContext)
	}

	for (unsigned int i = 0; i < sha3_length; i++) {
		printf("%02x", digest[i]);
	}

	// OPENSSL_free for cross-platform development
	OPENSSL_free(digest); 
	EVP_MD_CTX_destroy(messageDigestContext);

	return 0;
}
