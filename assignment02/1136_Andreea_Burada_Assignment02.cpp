//#include <stdio.h>
//#include <iostream>
//#include <string>
//#include <string.h>
//#include <malloc.h>
//#include <openssl/md5.h>
//#include <openssl/sha.h>
//
//using namespace std;
//
////Define and implement the class named MessageDigest as wrapper for OpenSSL message
////digest functionality.The class MessageDigest must contain the following items at least:
//
////1. Static fields for supported message digest algorithms(two algorithms at least)
////2. Constructor(s) to initialize the object MessageDigest.Please, document the
////constructor(s) within comments
////3. Methods to pass content to be digested and to get the message digest result.Please
////document within comments any method you add
////4. Destructor, if the case
//
//enum MD_algorithms { SHA1_alg = 1, MD5_alg = 2 };
//
//class MessageDigest {
//private:
//	MD_algorithms algorithm;
//	int messageChunkLength = 0;
//	string input;
//
//	void setMessageChunkSize() {
//		if (!this->algorithm) {
//			throw runtime_error("\n!!! Algorithm not initialized for MessageDigest object.");
//		}
//
//		switch (this->algorithm) {
//		case SHA1_alg:
//			this->messageChunkLength = 256;
//			break;
//		case MD5_alg:
//			this->messageChunkLength = 200;
//			break;
//		default:
//			throw runtime_error("\n!!! Algorithm type not supported.");
//		}
//	}
//
//	// method used to get chunk of input related to the message chunk length
//	// if input is smaller in size than the message chunk size, the remainder of the input will be returned
//	unsigned char* getInputChunk() {
//		unsigned char* inputChunk;
//		char* test;
//		if (this->input.size() > this->messageChunkLength) {
//			inputChunk = (unsigned char*)malloc(this->messageChunkLength + 1);
//			char* test = (char*)malloc(this->messageChunkLength + 1);
//			memcpy(inputChunk, this->input.c_str(), this->messageChunkLength);
//			inputChunk[this->messageChunkLength] = NULL;
//			// trim the input to remove the input chunk extracted
//			this->input = this->input.substr(this->messageChunkLength);
//		}
//		else {
//			inputChunk = (unsigned char*)malloc(this->input.size() + 1);
//			memcpy(inputChunk, this->input.c_str(), this->input.size());
//			inputChunk[this->input.size()] = NULL;
//		}
//		return inputChunk;
//	}
//
//	unsigned char* digestMessageSHA1() {
//		string inputBackup = this->input;
//		SHA_CTX context;
//		unsigned char finalDigest[SHA_DIGEST_LENGTH];
//		SHA1_Init(&context);
//
//		int inputLength = this->input.size();
//		unsigned char* inputBuffer = NULL;
//		while (inputLength > 0) {
//			inputBuffer = this->getInputChunk();
//			if (inputLength > this->messageChunkLength) {
//				SHA1_Update(&context, inputBuffer, this->messageChunkLength);
//			}
//			else {
//				SHA1_Update(&context, inputBuffer, inputLength);
//			}
//			inputLength -= this->messageChunkLength;
//			free(inputBuffer);
//		}
//
//		SHA1_Final(finalDigest, &context);
//		// restore input
//		this->input = inputBackup;
//		return finalDigest;
//	}
//
//	unsigned char* digestMessageMD5() {
//		string inputBackup = this->input;
//		MD5_CTX context;
//		unsigned char finalDigest[MD5_DIGEST_LENGTH];
//		MD5_Init(&context);
//
//		int inputLength = this->input.size();
//		unsigned char* inputBuffer = NULL;
//		while (inputLength > 0) {
//			inputBuffer = this->getInputChunk();
//			if (inputLength > this->messageChunkLength) {
//				MD5_Update(&context, inputBuffer, this->messageChunkLength);
//			}
//			else {
//				MD5_Update(&context, inputBuffer, inputLength);
//			}
//			inputLength -= this->messageChunkLength;
//			free(inputBuffer);
//		}
//
//		MD5_Final(finalDigest, &context);
//		// restore input
//		this->input = inputBackup;
//		return finalDigest;
//	}
//
//public:
//	// input: algorithm - MessageDigest algorithms enum type (sha1, md5)
//	MessageDigest(MD_algorithms algorithm) {
//		this->setAlgorithm(algorithm);
//	}
//
//	// input: algorithm - MessageDigest algorithms enum type (sha1, md5)
//	// input - string
//	MessageDigest(string input, MD_algorithms algorithm) {
//		this->setAlgorithm(algorithm);
//		this->setInput(input);
//	}
//
//	void setInput(string input) {
//		if (input.size() < 1) {
//			throw runtime_error("\n!!! Input length cannot be zero.");
//		}
//		this->input = input;
//	}
//
//	void setAlgorithm(MD_algorithms algorithm) {
//		this->algorithm = algorithm;
//		this->setMessageChunkSize();
//	}
//
//	MD_algorithms getAlgorithm() {
//		return this->algorithm;
//	}
//
//	// method will calculate the message digest depending on the chosen algorithm
//	// the input needs to be set before calling the digestMessage method, either by constructor or setter
//	// output: unsigned char array representing the message digest
//	unsigned char* digestMessage() {
//		if (!this->algorithm) {
//			throw runtime_error("\n!!! Algorithm not initialized for MessageDigest object.");
//		}
//
//		if (this->input.size() < 1) {
//			cout << "\nInput is empty. Cannot compute message digest.";
//			return NULL;
//		}
//
//		switch (this->algorithm) {
//		case SHA1_alg:
//			return this->digestMessageSHA1();
//		case MD5_alg:
//			return this->digestMessageMD5();
//		default:
//			throw runtime_error("\n!!! Cannot digest message. Algorithm type not supported.");
//		}
//	}
//
//	// static helper function to display the message digest in Hex
//	// algorithm type must be specified in order to determine the digest length
//	static void printMessageDigest(unsigned char* messageDigest, MD_algorithms algorithm) {
//		int messageDigestLength;
//		switch (algorithm) {
//			case SHA1_alg:
//				messageDigestLength = SHA_DIGEST_LENGTH;
//				break;
//			case MD5_alg:
//				messageDigestLength = MD5_DIGEST_LENGTH;
//				break;
//			default:
//				throw runtime_error("\n!!! Cannot display message digest. Algorithm type not supported.");
//		}
//
//		for (int i = 0; i < messageDigestLength; i++) {
//			printf("%02X ", messageDigest[i]);
//		}
//	}
//
//	void print() {
//		cout << "\nMessageDigest - algorithm = " << (this->algorithm == 1 ? "SHA-1" : "MD5")
//		<< ", message chunk size = " << this->messageChunkLength << ", input = " << this->input;
//	}
//
//	static const MD_algorithms sha1;
//	static const MD_algorithms md5;
//};
//
//const MD_algorithms MessageDigest::sha1 = MD_algorithms::SHA1_alg;
//const MD_algorithms MessageDigest::md5 = MD_algorithms::MD5_alg;
//
//void main() {
//	try {
//		MessageDigest sha1Test(MessageDigest::sha1), md5Test("This is a message that will be hashed.", MessageDigest::md5);
//		// set input for sha-1
//		sha1Test.setInput("This is a second message that will be hashed.");
//		// obtain message digest for both algorithms
//		cout << "\nSHA-1 ->\t\t\t";
//		unsigned char* sha1Result = sha1Test.digestMessage();
//		MessageDigest::printMessageDigest(sha1Result, sha1Test.getAlgorithm());
//
//		cout << "\nMD5 ->\t\t\t\t";
//		unsigned char* md5Result = md5Test.digestMessage();
//		MessageDigest::printMessageDigest(md5Result, md5Test.getAlgorithm());
//
//		// change inputs so they are over the chunk size
//
//		sha1Test.setInput("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque faucibus dui at lobortis lobortis. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Duis dictum dui dolor, quis ultricies sapien venenatis at. Aliquam sed ligula. ");
//		md5Test.setInput("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque faucibus dui at lobortis lobortis. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Duis dictum dui dolor, quis ultricies sapien venenatis at. Aliquam sed ligula. ");
//
//		cout << "\nSHA-1 (input > 256 B) ->\t";
//		sha1Result = sha1Test.digestMessage();
//		MessageDigest::printMessageDigest(sha1Result, sha1Test.getAlgorithm());
//
//		cout << "\nSHA-1 (input > 200 B) ->\t";
//		md5Result = md5Test.digestMessage();
//		MessageDigest::printMessageDigest(md5Test.digestMessage(), md5Test.getAlgorithm());
//	}
//	catch (exception& e) {
//		cout << "Error! - " << e.what();
//	}
//}