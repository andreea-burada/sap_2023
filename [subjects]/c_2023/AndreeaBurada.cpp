#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#define MESSAGE_CHUNK 256
#define _BUFFER 128

unsigned char* hashPassword(unsigned char* _password) {
	// create local copy of password
	int _p_length = strlen((char*)_password);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	unsigned char _final_digest[SHA256_DIGEST_LENGTH];

	SHA256_Update(&ctx, _password, _p_length);

	SHA256_Final(_final_digest, &ctx);

	return _final_digest;
}

void writeHexToFile(unsigned char* buffer, int bufferLength, FILE* file) {
	for (int i = 0; i < bufferLength; i++) {
		fprintf(file, "%02X", (unsigned char) buffer[i]);
	}
	fputs("\r", file);
}

unsigned char* fromAsciiToByte(char* input) {
	unsigned char* ptr, pair[2];
	long int result;
	unsigned char * bytes = (unsigned char*)malloc(32);	// hardcoded for SHA-256
	ptr = (unsigned char*) input;
	for (unsigned char i = 0; i < 64; i += 2) {
		memcpy(pair, ptr, 2);
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
	memcpy(_IV, IV, 16);

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
		unsigned char _line_buffer[_BUFFER];
		int _buffer_index = 0;
		while ((_char = fgetc(wordlistFile)) != EOF) {
			// get characters until '\r'	
			if (_char != '\r') {
				_line_buffer[_buffer_index++] = _char;
			}
			else {
				// add '\0' at the end of the line buffer
				_line_buffer[_buffer_index] = '\0';

				// compute hash with salt
				unsigned char* _temp_hash = hashPassword(_line_buffer);

				// write password to file
				writeHexToFile(_temp_hash, SHA256_DIGEST_LENGTH, hashesFile);
				//fwrite(_line_buffer, 1, SHA256_DIGEST_LENGTH, hashesFile);

				// reset index to get new line
				_buffer_index = 0;
				memset(_line_buffer, NULL, _BUFFER);

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
		// get IV and key from file
		FILE* aesConfig, *encFile;
		err2 = fopen_s(&aesConfig, "aes-cbc.bin", "rb");
		err3 = fopen_s(&encFile, "enc-sha256.txt", "wb");
		if (err2 == 0 && err3 == 0) {
			unsigned char IV[16], aesKey[256 / 8];
			fread(IV, 1, 16, aesConfig);
			fread(aesKey, 1, 256 / 8, aesConfig);
			// set key
			AES_KEY aes_key;
			fclose(aesConfig);

			char _char;
			char _line_buffer[SHA256_DIGEST_LENGTH + 1];
			unsigned char *_converted_line;
			int _buffer_index = 0;
			while ((_char = fgetc(hashesFile)) != EOF) {
				// get characters until '\r'	
				if (_char != '\r') {
					_line_buffer[_buffer_index++] = _char;
				}
				else {

					// convert from string of hex to unsigned char[]
					_converted_line = fromAsciiToByte(_line_buffer);

					// encrypt
					AES_set_encrypt_key(aesKey, 256, &aes_key);
					unsigned char* _temp_buffer = encryptAES(_converted_line, IV, aes_key);
					//unsigned char* _temp_buffer = encryptAES(_line_buffer, IV, &aes_key);

					// write password to file
					writeHexToFile(_temp_buffer, 32, encFile);

					// reset index to get new line
					free(_temp_buffer);
					free(_converted_line);
					_buffer_index = 0;
					memset(_line_buffer, NULL, SHA256_DIGEST_LENGTH + 1);
				}
			}
			fclose(hashesFile);
			fclose(encFile);
		}
	}
	return 0;
}