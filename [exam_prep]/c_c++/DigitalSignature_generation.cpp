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
		FILE* destionationFile = NULL;
		errno_t err;
		SHA256_CTX context;

		unsigned char finalDigest[SHA256_DIGEST_LENGTH];
		SHA256_Init(&context);
		unsigned char* fileBuffer = NULL;

		err = fopen_s(&sourceFile, argv[1], "rb");	    
		fseek(sourceFile, 0, SEEK_END);
		int fileLength = ftell(sourceFile);
		fseek(sourceFile, 0, SEEK_SET);

		fileBuffer = (unsigned char*)malloc(fileLength);
		fread(fileBuffer, fileLength, 1, sourceFile);
		unsigned char* tmpBuffer = fileBuffer;

		while (fileLength > 0) {
			if (fileLength > SHA256_DIGEST_LENGTH) {
				SHA256_Update(&context, tmpBuffer, SHA256_DIGEST_LENGTH);
			}
			else {
				SHA256_Update(&context, tmpBuffer, fileLength);
			}
			fileLength -= SHA256_DIGEST_LENGTH;
			tmpBuffer += SHA256_DIGEST_LENGTH;
		}

		SHA256_Final(finalDigest, &context);
			  
		// print the SHA-256 hash
		printf("SHA(256) = ");
		for( int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02X ", finalDigest[i]);        	
		printf("\n");
		  	
		fclose(sourceFile);

		err = fopen_s(&destionationFile, argv[2], "wb");

		RSA* privateKey;
		FILE* privateKeyFile;

		unsigned char* buffer = NULL;
		unsigned char* encryptedBuffer = NULL;
		unsigned char* decryptedBuffer = NULL;

		//unsigned char finalDigest[] = {
		//	0x99, 0x92, 0x62, 0x83, 0xe5, 0xa5, 0x49, 0x80,
		//	0xf1, 0x28, 0xd8, 0x04, 0x24, 0x47, 0xef, 0x87,
		//	0xae, 0xb1, 0x39, 0xd5, 0x65, 0xd4, 0x90, 0xcd,
		//	0xbd, 0x65, 0x1f, 0xdf, 0xec, 0x67, 0xfc, 0xfc
		//};

		//unsigned char finalDigest[] = {  // MD5  
		//	0x06, 0x48, 0x2B, 0x1F, 0x3E, 0xD9, 0x61, 0x44, 
		//	0xFC, 0x9F, 0x83, 0x57, 0x1E, 0xCE, 0x8D, 0x39
		//};

		privateKey = RSA_new();

		privateKeyFile = fopen("privKeySender.pem", "r");
		privateKey = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
		fclose(privateKeyFile);

		buffer = (unsigned char*)malloc(sizeof(finalDigest));
		memcpy(buffer, finalDigest, sizeof(finalDigest));

		// encryptedBuffer buffer to store the digital signature; there is one single RSA block for the signature
		encryptedBuffer = (unsigned char*)malloc(RSA_size(privateKey)); //RSA_size => 1024 bits/128 bytes

		RSA_private_encrypt(sizeof(finalDigest), buffer, encryptedBuffer, privateKey, RSA_PKCS1_PADDING); // encryption for e-signature made by using the PRIVATE key

		printf("Signature(RSA) = ");
		printf("\n");
		for (int i = 0; i < RSA_size(privateKey); i++)
		{
			printf("%02X ", encryptedBuffer[i]);
		}
		printf("\n");

		// write the content of encryptedBuffer with digital signature into a file
		fwrite(encryptedBuffer, RSA_size(privateKey), 1, destionationFile); // write the e-sign into the file

		fclose(destionationFile);

		free(encryptedBuffer);
		free(buffer);

		RSA_free(privateKey);
	}
	else {
		printf("\n Usage mode: OpenSSLProj.exe fSrc.txt eSignFsrc.txt");
		return 1;
	}

	return 0;
}