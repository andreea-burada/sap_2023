#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

int main(int argc, char** argv)
{
	if (argc == 3) {
		FILE* sourceFile = NULL;
		FILE* signatureFile = NULL;
		errno_t err;
		SHA256_CTX context;

		// Step #1 Compute the message digest for the restored plaintext
		unsigned char finalDigest[SHA256_DIGEST_LENGTH];
		unsigned char* fileBuffer = NULL;
		SHA256_Init(&context);

		err = fopen_s(&sourceFile, argv[1], "rb");
		fseek(sourceFile, 0, SEEK_END);
		int fileLen = ftell(sourceFile);
		fseek(sourceFile, 0, SEEK_SET);

		fileBuffer = (unsigned char*)malloc(fileLen);
		fread(fileBuffer, fileLen, 1, sourceFile);
		unsigned char* tmpBuffer = fileBuffer;

		while (fileLen > 0) {
			if (fileLen > SHA256_DIGEST_LENGTH) {
				SHA256_Update(&context, tmpBuffer, SHA256_DIGEST_LENGTH);
			}
			else {
				SHA256_Update(&context, tmpBuffer, fileLen);
			}
			fileLen -= SHA256_DIGEST_LENGTH;
			tmpBuffer += SHA256_DIGEST_LENGTH;
		}

		SHA256_Final(finalDigest, &context);

		printf("\n SHA-256 content computed: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02X ", finalDigest[i]);
		printf("\n");

		fclose(sourceFile);

		// Step #2 Decrypt the content of e-signature and compare it with the message digest resulted from Stage #1
		err = fopen_s(&signatureFile, argv[2], "rb");

		RSA* publicKey;
		FILE* publicKeyHandler;
		unsigned char* buffer = NULL;
		unsigned char* restoredBuffer = NULL;

		publicKey = RSA_new();

		publicKeyHandler = fopen("pubKeySender.pem", "r");
		publicKey = PEM_read_RSAPublicKey(publicKeyHandler, NULL, NULL, NULL);
		fclose(publicKeyHandler);

		buffer = (unsigned char*)malloc(RSA_size(publicKey));
		// there is one single ciphertext block
		fread(buffer, RSA_size(publicKey), 1, signatureFile);

		// 32 is the length of the SHA-256 algorithm result
		restoredBuffer = (unsigned char*)malloc(SHA256_DIGEST_LENGTH); 

		// decryption of the e-sign performed with the RSA public key
		RSA_public_decrypt(RSA_size(publicKey), buffer, restoredBuffer, publicKey, RSA_PKCS1_PADDING);

		fclose(signatureFile);

		printf("\n SHA-256 content decrypted from digital signature file: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02X ", restoredBuffer[i]);
		printf("\n");

		// the two message digests are compared: computed vs. decrypted from e-sign
		if (memcmp(restoredBuffer, finalDigest, SHA256_DIGEST_LENGTH) == 0) 
			printf("\n Signature OK!\n");
		else
			printf("\n Signature does not validate the message!\n");

		free(restoredBuffer);
		free(buffer);

		RSA_free(publicKey);
	}
	else {
		printf("\n Usage mode: OpenSSLProj.exe fSrc.txt eSignFsrc.txt");
		return 1;
	}

	return 0;
}