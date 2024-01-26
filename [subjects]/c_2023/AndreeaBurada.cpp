#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS

#define MESSAGE_CHUNK 256
#define _BUFFER 128

unsigned char* hashPassword(unsigned char* _password) {
	int passwordLength = strlen((char*)_password);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	unsigned char finalDigest[SHA256_DIGEST_LENGTH];

	SHA256_Update(&ctx, _password, passwordLength);

	SHA256_Final(finalDigest, &ctx);

	return finalDigest;
}

void writeHexToFile(unsigned char* buffer, int bufferLength, FILE* file) {
	for (int i = 0; i < bufferLength; i++) {
		fprintf(file, "%02X", (unsigned char) buffer[i]);
	}
	fputs("\n", file);
}

unsigned char* fromAsciiToByte(unsigned char* input) {
	unsigned char* ptr, pair[2];
	long int result;
	// strlen only works if the input is null byte terminated !!!
	unsigned char* bytes = (unsigned char*)malloc(strlen((char*)input) / 2);
	ptr = input;
	for (unsigned char i = 0; i < strlen((char*)input); i += 2) {
		memcpy(&pair, ptr, 2);
		result = strtol((char*)pair, NULL, 16);
		bytes[i / 2] = result;
		ptr += 2;
	}
	return bytes;
}

unsigned char* encryptAES(unsigned char* input, unsigned char* IV, AES_KEY key) {
	// allocate space for ciphertext
	unsigned char* ciphertext = (unsigned char*)malloc(32);
	unsigned char _IV[16];
	memcpy(&_IV, IV, 16);

	AES_cbc_encrypt(input, ciphertext, 32, &key, _IV, AES_ENCRYPT);

	return ciphertext;
}

int main()
{
	// 1. In order to secure the users’ credentials, you have to apply SHA-256 for all the passwords stored 
	// by the text file.
		// The hashed content must meet the following requirements(10p) :
		// - To be saved into a separate text file named as hashes.txt.
		// - Each line of the output file hashes.txt represents the hexadecimal format of the hashed content
		// for the password stored on the same line within the input password file.
	FILE* wordlistFile = NULL, * hashesFile = NULL;
	errno_t err, err2, err3;

	unsigned char* fileBuffer = NULL;

	err = fopen_s(&wordlistFile, "wordlist.txt", "rb");
	if (err == 0) {
		err2 = fopen_s(&hashesFile, "hashes.txt", "wb");
		char _char;
		unsigned char lineBuffer[_BUFFER];
		int bufferIndex = 0;
		while ((_char = fgetc(wordlistFile)) != EOF) {
			// get characters until '\r'	
			if (_char != '\r') {
				lineBuffer[bufferIndex++] = _char;
			}
			else {
				// add '\0' at the end of the line buffer
				lineBuffer[bufferIndex] = '\0';

				// compute hash with salt
				unsigned char* _temp_hash = hashPassword(lineBuffer);

				// write password to file
				writeHexToFile(_temp_hash, SHA256_DIGEST_LENGTH, hashesFile);

				// reset index to get new line
				bufferIndex = 0;
				memset(lineBuffer, NULL, _BUFFER);

				// eat one character to consume the /n
				fgetc(wordlistFile);
			}
		}
		fclose(wordlistFile);
		fclose(hashesFile);
	}

	//  2. In hashes.txt each line is encrypted by using the AES - CBC - 256 scheme.The IV and AES - 256 key
	//	are stored by the binary file named aes - cbc.bin, where IV is first and it is followed by AES - 256 key.
	//	The encrypted content must meet the following requirements(10p) :
	//		- To be saved into a separate text file named as enc - sha256.txt.
	//		- Each line of the output file enc - sha256.txt represents the hexadecimal format of the encrypted
	//	SHA - 256 stored on the same line in hashes.txt.
	err = fopen_s(&hashesFile, "hashes.txt", "rb");

	if (err == 0) {
		FILE* aesConfig, *encFile;
		err2 = fopen_s(&aesConfig, "aes-cbc.bin", "rb");
		err3 = fopen_s(&encFile, "enc-sha256.txt", "wb");

		if (err2 == 0 && err3 == 0) {
			// get IV and key from file
			unsigned char IV[16], aesKey[256 / 8];
			fread(IV, 1, 16, aesConfig);
			fread(aesKey, 1, 256 / 8, aesConfig);
			fclose(aesConfig);

			// set key
			AES_KEY aes_key;
			AES_set_encrypt_key(aesKey, 256, &aes_key);

			char _char;
			unsigned char lineBuffer[SHA256_DIGEST_LENGTH * 2 + 1], * lineBufferInBytes, * encryptedHash;
			memset(&lineBuffer, 0x00, SHA256_DIGEST_LENGTH * 2 + 1);

			int bufferIndex = 0;

			while ((_char = fgetc(hashesFile)) != EOF) {
				// get characters until '\r'	
				if (_char != '\n') {
					lineBuffer[bufferIndex++] = _char;
				}
				else {
					// convert from string of hex to unsigned char[]
					lineBufferInBytes = fromAsciiToByte(lineBuffer);

					// encrypt
					encryptedHash = encryptAES(lineBufferInBytes, IV, aes_key);

					// write password to file
					writeHexToFile(encryptedHash, 32, encFile);
					free(encryptedHash);

					// reset index to get new line
					bufferIndex = 0;
					memset(&lineBuffer, 0x00, SHA256_DIGEST_LENGTH * 2);
				}
			}
			fclose(hashesFile);
			fclose(encFile);
		}
	}

	// 3. Generate the digital signature for the file enc-sha256.txt and save that signature into a file called 
	// esign.sig.The message digest algorithm is SHA - 256, and the 1024 - bit RSA key for signature
	// generation is stored in a PEM file named as rsa - key.pem. (5p)
	FILE* sourceFile = NULL;
	err = fopen_s(&sourceFile, "enc-sha256.txt", "rb");
	fseek(sourceFile, 0, SEEK_END);
	int sourceFileLength = ftell(sourceFile);
	fseek(sourceFile, 0, SEEK_SET);

	FILE* keyHandler, *destinationFile = NULL;
	errno_t keyErr = fopen_s(&keyHandler, "rsa-key.pem", "r");
	// load RSA public key components into RSA structure
	RSA* pemKey = PEM_read_RSAPrivateKey(keyHandler, NULL, NULL, NULL);
	fclose(keyHandler);

	err = fopen_s(&destinationFile, "esign.sig", "wb");

	// allocate buffer to store plaintext chunks, eack chunck has 128 bytes == RSA key length
	unsigned char* sourceBuffer = (unsigned char*)malloc(RSA_size(pemKey) + 1);
	sourceBuffer[RSA_size(pemKey)] = 0x00;	// null byte terminator

	// allocate buffer to store the ciphertext on 128 bytes same like the RSA key length
	unsigned char* ciphertextBuffer = NULL;
	ciphertextBuffer = (unsigned char*)malloc(RSA_size(pemKey));

	if (sourceFileLength != RSA_size(pemKey)) {
		while (fread_s(sourceBuffer, RSA_size(pemKey), sizeof(unsigned char), RSA_size(pemKey), sourceFile) == RSA_size(pemKey)) {
			// encryption block-by-block, each block has RSA key length (1024 bits)
			// because the block is filled in fully, then there is no padding to be used here

			// if the plaintext is matching the number of blocks, the last full block will be encrypted without padding
			RSA_private_encrypt(RSA_size(pemKey), sourceBuffer, ciphertextBuffer, pemKey, RSA_NO_PADDING);
			fwrite(ciphertextBuffer, sizeof(unsigned char), RSA_size(pemKey), destinationFile);
		}
	}
	else {
		fread_s(sourceBuffer, RSA_size(pemKey), sizeof(unsigned char), RSA_size(pemKey), sourceFile);
	}

	// if there are additional bytes to be encrypted
	if (sourceFileLength % RSA_size(pemKey))
	{
		// encryption of the last block with padding because it could be a partial block (less 1024 bits)
		RSA_private_encrypt(sourceFileLength % RSA_size(pemKey), sourceBuffer, ciphertextBuffer, pemKey, RSA_PKCS1_PADDING);
		fwrite(ciphertextBuffer, sizeof(unsigned char), RSA_size(pemKey), destinationFile);
	}

	return 0;
}