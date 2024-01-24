
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <openssl/aes.h>

int main(int argc, char** argv)
{
	if (argc == 5) {
		FILE* sourceFile = NULL, * destinationFile = NULL;

		char option[3];
		char mode[7];
		strcpy(option, argv[1]);
		strcpy(mode, argv[2]);

		AES_KEY aes_key;
		unsigned char* inBuffer = NULL;
		unsigned char* outBuffer;
		unsigned char IV[16];
		unsigned char userSymmetricKey[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
											   0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
		unsigned char wrongSymmetricKey[16] = { 0x11, 0x11, 0xf2, 0xf3, 0xc4, 0x55, 0xa6, 0xa7, 
												0xa0, 0xa1, 0x92, 0x93, 0x94, 0x95, 0x56, 0x77 };

		// encryption
		if (strcmp(option, "-e") == 0) {
			fopen_s(&sourceFile, argv[3], "rb");
			fopen_s(&destinationFile, argv[4], "wb");

			fseek(sourceFile, 0, SEEK_END);
			long int inLength = ftell(sourceFile); // inLength - file size in bytes
			fseek(sourceFile, 0, SEEK_SET);

			long int outLength = 0;

			// determine ciphertext length
			if ((inLength % 16) == 0)
				outLength = inLength;
			else
				// add extra 16B if not %16
				outLength = ((inLength / 16) * 16) + 16; // outLength - total size of the ciphertext after encryption

			inBuffer = (unsigned char*)malloc(outLength); // inBuffer - !!! allocated at outLen to avoid adressing outside the allocated area in heap
			outBuffer = (unsigned char*)malloc(outLength);
			memset(inBuffer, 0x00, outLength);

			fread(inBuffer, inLength, 1, sourceFile); // copy the file content into inBuffer (inLength less outLength)

			AES_set_encrypt_key(userSymmetricKey, 128, &aes_key); // set AES key for encryption (128 bits)

			// ECB encryption
			if (strcmp(mode, "-ecb") == 0) {
				for (int i = 0; i < (outLength / 16); i++)
					AES_encrypt(&(inBuffer[i * 16]), &(outBuffer[i * 16]), &aes_key); // AES-ECB encryption done block-by-block (AES block is 16 bytes)
			}
			// CBC encryption
			else {
				// IV is 01h 16 times
				// sizeof works because IV is static array of bytes
				memset(&IV, 0x01, sizeof(IV)); // set the content of the initialization vector (IV)
				AES_cbc_encrypt(inBuffer, outBuffer, outLength, &aes_key, IV, AES_ENCRYPT); // AES-CBC encryption done in one sigle step for entire plaintext as input
			}

			// size of the plaintext is saved into encrypted file to know how many bytes to restore at decryption time
			fwrite(&inLength, sizeof(inLength), 1, destinationFile); 
			// ciphertext saved into file
			fwrite(outBuffer, outLength, 1, destinationFile);

			fclose(destinationFile);
			fclose(sourceFile);

			free(outBuffer);
			free(inBuffer);
		}
		// decryption
		else {
			fopen_s(&sourceFile, argv[3], "rb");
			fopen_s(&destinationFile, argv[4], "wb");

			fseek(sourceFile, 0, SEEK_END);
			long int inLength = ftell(sourceFile) - 4; // inLength - ciphertext length
			fseek(sourceFile, 0, SEEK_SET);

			long int outLength = 0;

			fread(&outLength, sizeof(outLength), 1, sourceFile); // outLength - size of the restored message read from the first 4 bytes of the ciphertext file

			inBuffer = (unsigned char*)malloc(inLength);
			outBuffer = (unsigned char*)malloc(inLength);
			memset(inBuffer, 0x00, inLength);

			fread(inBuffer, inLength, 1, sourceFile); // inBuffer - ciphertext content

			//AES_set_decrypt_key(wrongSymmetricKey, 128, &aes_key);
			AES_set_decrypt_key(userSymmetricKey, 128, &aes_key); // set the AES key for decryption; must be the same as the one used for encryption

			// ECB decryption
			if (strcmp(mode, "-ecb") == 0) {
				for (int i = 0; i < (inLength / 16); i++)
					AES_decrypt(&(inBuffer[i * 16]), &(outBuffer[i * 16]), &aes_key); // AES-ECB decryption block-by-block
			}
			// CBC decryption
			else {
				memset(&IV, 0x02, sizeof(IV));
				AES_cbc_encrypt(inBuffer, outBuffer, inLength, &aes_key, IV, AES_DECRYPT); // AES-CBC decryption as oneshot operation
			}

			// restored message saved into a file
			fwrite(outBuffer, outLength, 1, destinationFile); 

			fclose(destinationFile);
			fclose(sourceFile);

			free(outBuffer);
			free(inBuffer);
		}
	}
	else {
		printf("\n Usage Mode: OpenSSLProj.exe -e -cbc sourceFile.txt destinationFile.txt");
		printf("\n Usage Mode: OpenSSLProj.exe -d -ecb sourceFile.txt destinationFile.txt");
		return 1;
	}
	printf("\n Process done.");
	return 0;
}
