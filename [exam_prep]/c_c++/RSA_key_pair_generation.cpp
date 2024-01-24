#include <stdio.h>
#include <malloc.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>


int main()
{
	RSA* rsaKP = NULL;

	// rsaKP = RSA_new(); // allocate storage for RSA openssl structure
	// RSA_generate_key includes RSA_new()
	rsaKP = RSA_generate_key(1024, 65535, NULL, NULL); // generate RSA key pair on 1k bits

	// validate the previous generated key pair
	RSA_check_key(rsaKP); 

	FILE* privateKeyFileHandler = NULL;
	// create file to store the RSA private key (in PEM format)
	fopen_s(&privateKeyFileHandler, "privateKeyReceiver.pem", "w+"); 
	// get the private key from RSA openssl structure and store it in the file in PEM format
	PEM_write_RSAPrivateKey(privateKeyFileHandler, rsaKP, NULL, NULL, 0, 0, NULL);
																	
	fclose(privateKeyFileHandler);

	FILE* publicKeyFileHandler = NULL;
	// create file to store the RSA public key
	fopen_s(&publicKeyFileHandler, "publicKeyReceiver.pem", "w+"); 
	// get the public key fro RSA openssl structure and store it in the file in PEM format
	PEM_write_RSAPublicKey(publicKeyFileHandler, rsaKP); 

	fclose(publicKeyFileHandler);

	// release the storage for RSA openssl structure
	RSA_free(rsaKP); 

	printf("\n The RSA key pair generated! \n");

	return 0;
}