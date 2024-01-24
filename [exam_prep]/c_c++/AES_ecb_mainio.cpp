#include <openssl/aes.h>
#include <stdio.h>

int main(int argc, char** argv)
{
	unsigned char plaintext[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
								  0xab, 0xcd, 0xef, 0xff, 0xfe, 0xff, 0xdc, 0xba,
								  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
								  0x10, 0x01, 0x20, 0x22, 0x3a, 0x3b, 0xd4, 0xd5,
								  0xff };
	unsigned char ciphertext[48];
	unsigned char restoringtext[48];

	// symetric AES key for 128, 192 and 256 bits 
	unsigned char key_128[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
								0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0 };
	unsigned char key_192[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
								0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
								0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53 };
	unsigned char key_256[] = { 0x01, 0x02, 0x03, 0x04, 0x50, 0x51, 0x52, 0x53,
								0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0a, 0xa0,
								0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
								0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0 };

	AES_KEY aes_key;

	// encryption according to AES-ECB
	// !!!sizeof here works because it is a static array!!!
	// AES_set_encrypt_key(key_128, (sizeof(key_128) * 8), &aes_key);
	AES_set_encrypt_key(key_192, (sizeof(key_192) * 8), &aes_key);
	// AES_set_encrypt_key(key_256, (sizeof(key_256) * 8), &aes_key);
	for(unsigned int i = 0; i < sizeof(plaintext); i += 16)
		AES_encrypt(&plaintext[i], &ciphertext[i], &aes_key);

	printf("Ciphertext for AES-ECB: ");
	for (unsigned int i = 0; i < sizeof(ciphertext); i++)
		printf("%02X", ciphertext[i]);

	// decryption according to AES-ECB
	// AES_set_decrypt_key(key_128, (sizeof(key_128) * 8), &aes_key);
	AES_set_decrypt_key(key_192, (sizeof(key_192) * 8), &aes_key);
	// AES_set_decrypt_key(key_256, (sizeof(key_256) * 8), &aes_key);
	for (unsigned int i = 0; i < sizeof(ciphertext); i += 16)
		AES_decrypt(&ciphertext[i], &restoringtext[i], &aes_key);

	printf("\nRestored plaintext for AES-ECB: ");
	for (unsigned int i = 0; i < sizeof(plaintext); i++)
		printf("%02X", restoringtext[i]);

	unsigned flag = 1;
	for (unsigned int i = 0; i < sizeof(plaintext) && flag; i++)
	{
		if (plaintext[i] != restoringtext[i])
			flag = 0;
	}
	if (!flag)
		printf("\nDecryption failed!\n");
	else
		printf("\nSuccessful decryption!\n");

	return 0;
}