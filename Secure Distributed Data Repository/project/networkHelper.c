/********************************NETWORKHELPER.C*********************************************
Module: networkHelper.c
Description: This module provides helper functions to both the client and the server which helps 
in the network communication over a secure encrypted and trusted channel
***********************************************************************************************/
#include "headers.h"
#include "networkHelper.h"
#include "genericHelper.h"

/******************************************************************************************
Function: getInAddr()
Description: Extracts and return the address from a sockaddr structure
******************************************************************************************/
void * getInAddr(struct sockaddr *saddr)
{
	if(saddr->sa_family == AF_INET)
	{
		return &(((struct sockaddr_in *)saddr)->sin_addr);
	}
	return &(((struct sockaddr_in6*) saddr)->sin6_addr);
}


/******************************************************************************************
Function: prepend()
Description: Function to prepend one string to another and return the updated string.
This is used to prepend the random iv to the cipher text which gets transferred to the 
other party allowing the decrypt using this prepended iv
******************************************************************************************/
unsigned char* prepend(unsigned char *prependTo, unsigned char *prependIt, size_t sizeofPrependTo, size_t sizeofPrependIt)
{
	//printf("prependTo: \n");
	//print_hex((const char *)prependTo, sizeofPrependTo);
	//printf("prependIt: \n");
	//print_hex((const char *)prependIt, sizeofPrependIt);
	prependTo = (unsigned char *)realloc(prependTo, sizeofPrependTo + sizeofPrependIt);
   	memmove(prependTo + sizeofPrependIt, prependTo, sizeofPrependTo);
   	memmove(prependTo, prependIt,sizeofPrependIt);
	//printf("returning: \n");
	//print_hex((const char *)prependTo, strlen((const char *)prependTo));
	return prependTo;
}


/******************************************************************************************
Function: encrypt()
Description: Function to encypt the plaintext with a 128-bit session key and a random iv 
using AES CBC random mode and return the iv prepended to the ciphertext
******************************************************************************************/
unsigned char * encrypt(unsigned char * key, unsigned char * plaintext, int plaintextLength, int *cipherLength)
{
	//printf("session key:\n");
	//print_hex((const char *)key, KEY_SIZE_IN_BYTES);
	unsigned char * iv = (unsigned char *)malloc(KEY_SIZE_IN_BYTES+1);
        memset(iv, 0, KEY_SIZE_IN_BYTES+1);
        int rc = RAND_bytes(iv, KEY_SIZE_IN_BYTES);
	//printf("iv: \n");
	//print_hex((const char *)iv, KEY_SIZE_IN_BYTES);
	EVP_CIPHER_CTX * ctx;
	if(!(ctx = EVP_CIPHER_CTX_new()))
	{
		fprintf(stderr, "Error in EVP_CIPHER_CTX_new()\n");
		return NULL;
	}	
        if(rc != 1)
        {
                fprintf(stderr, "RAND_bytes() failed.\n");
		return NULL;
        }
	*cipherLength = plaintextLength + 16;
	unsigned char * ciphertext = (unsigned char *)malloc(*cipherLength);	
	if(ciphertext == NULL)
	{
		fprintf(stderr, "Error in allocating memory for ciphertext in encrypt()\n");
		return NULL;
	}
	memset(ciphertext, 0, *cipherLength);
        int length = 0;
	if(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
	{
		fprintf(stderr, "Error in EVP_EncryptInit_ex.\n");
		return NULL;
	}
	if(EVP_EncryptUpdate(ctx, ciphertext, cipherLength, plaintext, plaintextLength) != 1)
	{
		fprintf(stderr, "Error in EVP_EncryptUpdate.\n");
		return NULL;
	}	
	if(EVP_EncryptFinal_ex(ctx, ciphertext+(*cipherLength), &length) != 1)
	{
		fprintf(stderr, "Error in EVP_EncryptFinal_ex.\n");
		return NULL;
	}
	(*cipherLength) += length;
	EVP_CIPHER_CTX_free(ctx);
	//printf("cipher text: \n");
	//print_hex((const char *)ciphertext, *cipherLength);
	unsigned char * ivWithCipher = prepend(ciphertext, iv, *cipherLength, KEY_SIZE_IN_BYTES);
	(*cipherLength)+= KEY_SIZE_IN_BYTES; 
	//printf("Returned: \n");
	//print_hex((const char *)ivWithCipher, *cipherLength);
	return ivWithCipher;
}


/*****************************************************************************************
Function: decrypt()
Description: Function to decrypt the ciphertext with a 128-bit session key and the iv
extracted from the start of the ciphertext using AES CBC random mode and return the 
plaintext
******************************************************************************************/
unsigned char * decrypt(unsigned char * receivedCipher, int receivedCipherLength, unsigned char * key, int * plaintextLength)
{
	EVP_CIPHER_CTX * ctx;
	if(!(ctx = EVP_CIPHER_CTX_new()))
	{
		fprintf(stderr, "Error in EVP_CIPHER_CTX_new()\n");
		return NULL;
	}	
	int cipherSize = receivedCipherLength - KEY_SIZE_IN_BYTES;
	unsigned char * iv = (unsigned char *)malloc(KEY_SIZE_IN_BYTES+1);
	if(iv == NULL)
	{
		fprintf(stderr, "Error in allocating memory for iv in decrypt()\n");
		return NULL;
	}
	unsigned char * cipher = (unsigned char *)malloc(cipherSize+1);
	if(cipher == NULL)
	{
		fprintf(stderr, "Error in allocating memory for cipher in decrypt()\n");
		return NULL;
	}
	memset(iv, 0, KEY_SIZE_IN_BYTES+1);
	memset(cipher, 0, cipherSize+1);
	memmove(iv, receivedCipher, KEY_SIZE_IN_BYTES);
	memmove(cipher, receivedCipher + KEY_SIZE_IN_BYTES, cipherSize);
	int length=0;
	*plaintextLength = cipherSize;
	unsigned char * plaintext = (unsigned char *)malloc(cipherSize);  
	if(plaintext == NULL)
	{
		fprintf(stderr, "Error in allocating memory for plaintext in decrypt()\n");
		exit(1);
	}
	//printf("iv: \n");
	//print_hex((const char *)iv, KEY_SIZE_IN_BYTES);
	//printf("key: \n");
	//print_hex((const char *)key, KEY_SIZE_IN_BYTES);
	//printf("Cipher: \n");
	//print_hex((const char *)cipher, cipherSize);
	memset(plaintext, 0, cipherSize);
	if(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
	{
		fprintf(stderr, "Error in EVP_DecryptInit_ex.\n");
		return NULL;
	}
	if(EVP_DecryptUpdate(ctx, plaintext, plaintextLength, cipher, cipherSize) != 1)
	{
		fprintf(stderr, "Error in EVP_DecryptUpdate.\n");
		return NULL;
	}
	if (EVP_DecryptFinal_ex(ctx, plaintext+(*plaintextLength), &length) != 1)
 	{
		fprintf(stderr, "Error in EVP_DecryptFinal_ex.\n");
		return NULL;
	}
	EVP_CIPHER_CTX_free(ctx);
	(*plaintextLength) += length;
	plaintext[*plaintextLength] = '\0';
	return plaintext;
}

/**************************************EOF**********************************************/
