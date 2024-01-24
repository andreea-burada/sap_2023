#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <time.h>

#pragma warning(disable:4996)

#define _BUFFER 128
#define _SALT "ismsap"

unsigned char* hashWithSalt(unsigned char* _password) {
	// create local copy of password
	int _p_length = strlen((char*)_password);
	unsigned char* __password;

	__password = (unsigned char*) malloc(_p_length + strlen(_SALT) + 1);
	if (__password != NULL) {
		memcpy(__password, _SALT, strlen(_SALT) + 1);
		memcpy(__password + 6, _password, _p_length + 1);

		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		unsigned char _final_digest[SHA256_DIGEST_LENGTH];

		SHA256_Update(&ctx, __password, strlen(__password));

		SHA256_Final(_final_digest, &ctx);

		free(__password);
		return _final_digest;
	}
	free(__password);
	return NULL;
}

void main() {
	FILE* _key_file;
	unsigned char _key[32];
	FILE* _password_file;
	unsigned char _password_encrypted[32];

	printf("Initializing Brute Force process...");

	// read AES key
	printf("\n\nReading AES key from \"aes.key\" file...");
	fopen_s(&_key_file, "aes.key", "rb");
	if (_key_file != NULL)
		fread(_key, sizeof(_key), 1, _key_file);
	printf("\nDone reading AES key.");

	// read encrypted hashed password
	printf("\n\nReading encrypted hashed password from \"pass.enc\" file...");
	fopen_s(&_password_file, "pass.enc", "rb");
	if (_password_file != NULL)
		fread(_password_encrypted, sizeof(_password_encrypted), 1, _password_file);
	printf("\nDone reading encrypted password.");

	// decrpyt the hashed password
	printf("\n\nDecrypting hashed password...");

	AES_KEY _aes_key;
	unsigned char _password_decrypted[32];

	AES_set_decrypt_key(_key, sizeof(_key) * 8, &_aes_key);

	for (unsigned int i = 0; i < sizeof(_password_encrypted); i += 16)
		AES_decrypt(&_password_encrypted[i], &_password_decrypted[i], &_aes_key);

	printf("\nDone decrpyting hashed password. Result: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X ", _password_decrypted[i]);
	}

	// iterating through wordlist
	FILE* _wordlist;

	printf("\n\nOpening wordlist \"ignis-10M.txt\"...");
	_wordlist = fopen("ignis-10M.txt", "rb");
	if (_wordlist == NULL) {
		printf("Wordlist file could not be opened!");
		return;
	}
	printf("\nDone opening wordlist.");

	char _char;
	unsigned char _line_buffer[_BUFFER];
	int _buffer_index = 0;

	printf("\n\nBeginning Brute Force...");

	// measuring brute force execution time
	clock_t _time;
	_time = clock();

	while ((_char = fgetc(_wordlist)) != EOF) {
		// get characters until '\n'	
		if (_char != '\n') {
			_line_buffer[_buffer_index++] = _char;
		}
		else {
			// add '\0' at the end of the line buffer
			_line_buffer[_buffer_index] = '\0';

			// compute hash with salt
			unsigned char* _temp_hash = hashWithSalt(_line_buffer);
			unsigned _ok = 1;
			for (int i = 0; i < 32 && _ok == 1; i++) {
				if (_temp_hash[i] != _password_decrypted[i]) {
					_ok = 0;
				}
			}

			if (_ok == 1) {
				_time = clock() - _time;
				printf("\n\nBingo! We found the password:\t%s\nPassword found in %.3f seconds.\n", _line_buffer, ((double)_time)/CLOCKS_PER_SEC);
				break;
			}

			// reset index to get new line
			_buffer_index = 0;
			memset(_line_buffer, NULL, _BUFFER);
		}	
	}

	printf("\nBrute Force finalized.");
}