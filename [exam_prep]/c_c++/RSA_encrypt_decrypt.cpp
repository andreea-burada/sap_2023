#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main(int argc, char** argv)
{
	if (argc == 4) {
		FILE* sourceFile = NULL;
		FILE* destinationFile = NULL;
		FILE* restoredSourceFile = NULL;
		errno_t err;

		err = fopen_s(&sourceFile, argv[1], "rb");
		fseek(sourceFile, 0, SEEK_END);
		int sourceFileLength = ftell(sourceFile);
		fseek(sourceFile, 0, SEEK_SET);


		RSA* publicKey;
		RSA* privateKey;
		FILE* keyHandler;

		unsigned char* ciphertextBuffer = NULL;
		unsigned char* restoredBuffer = NULL;

		// privateKey = RSA_new();
		// publicKey = RSA_new();

		// --- RSA encryption ---
		keyHandler = fopen("pubKeyReceiver.pem", "r");
		// load RSA public key components into RSA structure
		publicKey = PEM_read_RSAPublicKey(keyHandler, NULL, NULL, NULL); 
		fclose(keyHandler);

		err = fopen_s(&destinationFile, argv[2], "wb");

		// allocate buffer to store plaintext chunks, eack chunck has 128 bytes == RSA key length
		unsigned char* sourceBuffer = (unsigned char*)malloc(RSA_size(publicKey) + 1); 
		sourceBuffer[RSA_size(publicKey)] = 0x00;	// null byte terminator

		// allocate buffer to store the ciphertext on 128 bytes same like the RSA key length
		ciphertextBuffer = (unsigned char*)malloc(RSA_size(publicKey)); 

		if (sourceFileLength != RSA_size(publicKey)) {
			while (fread_s(sourceBuffer, RSA_size(publicKey), sizeof(unsigned char), RSA_size(publicKey), sourceFile) == RSA_size(publicKey)) {
				// encryption block-by-block, each block has RSA key length (1024 bits)
				// because the block is filled in fully, then there is no padding to be used here

				// if the plaintext is matching the number of blocks, the last full block will be encrypted without padding
				RSA_public_encrypt(RSA_size(publicKey), sourceBuffer, ciphertextBuffer, publicKey, RSA_NO_PADDING);
				fwrite(ciphertextBuffer, sizeof(unsigned char), RSA_size(publicKey), destinationFile);
			}
		}
		else {
			fread_s(sourceBuffer, RSA_size(publicKey), sizeof(unsigned char), RSA_size(publicKey), sourceFile);
		}

		// if there are additional bytes to be encrypted
		if (sourceFileLength % RSA_size(publicKey)) 
		{
			// encryption of the last block with padding because it could be a partial block (less 1024 bits)
			RSA_public_encrypt(sourceFileLength % RSA_size(publicKey), sourceBuffer, ciphertextBuffer, publicKey, RSA_PKCS1_PADDING); 
			fwrite(ciphertextBuffer, sizeof(unsigned char), RSA_size(publicKey), destinationFile);
		}

		// --- RSA decryption ---
		keyHandler = fopen("privKeyReceiver.pem", "r");
		// load RSA private key components into RSA openssl structure
		privateKey = PEM_read_RSAPrivateKey(keyHandler, NULL, NULL, NULL); 
		fclose(keyHandler);

		free(ciphertextBuffer);	// this is because we used it beforehand
		// buffer to store the inpur ciphertext block with 128 bytes 
		ciphertextBuffer = (unsigned char*)malloc(RSA_size(publicKey)); 
		// buffer to store the restored block of the plaintext
		restoredBuffer = (unsigned char*)malloc(RSA_size(publicKey)); 
		fclose(destinationFile);

		fopen_s(&destinationFile, argv[2], "rb");
		fseek(destinationFile, 0, SEEK_END);
		int destinationFileLength = ftell(destinationFile);
		fseek(destinationFile, 0, SEEK_SET);

		// number of ciphertext blocks
		int maxChunks = destinationFileLength / RSA_size(publicKey); 
		int currentChunk = 1;

		err = fopen_s(&restoredSourceFile, argv[3], "wb");

		if (destinationFileLength != RSA_size(publicKey)) {
			while (fread_s(ciphertextBuffer, RSA_size(publicKey), sizeof(unsigned char), RSA_size(publicKey), destinationFile) == RSA_size(publicKey)) {
				// 1 to (maxChunks - 1) are considered here because no padding
				if (currentChunk != maxChunks) { 
					// decryption done block-by-block; each block must have 1024 bits as length
					// because each block is filled in fully, there is no padding to be added here
					RSA_private_decrypt(RSA_size(publicKey), ciphertextBuffer, restoredBuffer, privateKey, RSA_NO_PADDING);
					fwrite(restoredBuffer, sizeof(unsigned char), RSA_size(publicKey), restoredSourceFile);
					currentChunk++;
				}
			}
		}
		else {
			fread_s(ciphertextBuffer, RSA_size(publicKey), sizeof(unsigned char), RSA_size(publicKey), destinationFile);
		}


		// could be a partial block; the padding must be used to meet the length of RSA key
		if (sourceFileLength % RSA_size(publicKey))
		{		
			RSA_private_decrypt(RSA_size(publicKey), ciphertextBuffer, restoredBuffer, privateKey, RSA_PKCS1_PADDING);
			fwrite(restoredBuffer, sizeof(unsigned char), sourceFileLength % RSA_size(publicKey), restoredSourceFile);
			//fwrite(restoredBuffer, sizeof(unsigned char), RSA_size(publicKey), restoredSourceFile); // write the restored/decrypted block together with the padding (PKCS1)
		}
		// the last block to decrypted is a full block in plaintext; no padding required for decryption
		else
		{	
			RSA_private_decrypt(RSA_size(publicKey), ciphertextBuffer, restoredBuffer, privateKey, RSA_NO_PADDING);
			fwrite(restoredBuffer, sizeof(unsigned char), RSA_size(publicKey), restoredSourceFile);
		}


		free(restoredBuffer);
		free(ciphertextBuffer);
		free(sourceBuffer);

		RSA_free(publicKey);
		RSA_free(privateKey);

		fseek(restoredSourceFile, 0, SEEK_END);
		printf("Nr. of bytes on the decrypted file: %d \n", ftell(restoredSourceFile));
		fseek(sourceFile, 0, SEEK_END);
		printf("Nr. of bytes on the input file: %d", ftell(sourceFile));

		fclose(sourceFile);
		fclose(restoredSourceFile);
		fclose(destinationFile);

	}
	else {
		printf("\n Usage mode: OpenSSLProj.exe f1.txt encryptf1.txt f9.txt");
		return 1;
	}

	return 0;
}