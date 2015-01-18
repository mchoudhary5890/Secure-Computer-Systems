/********************************HANDSHAKEHELPER.C*********************************************
Module: handshakeHelper.c
Description: This module provides helper functions to both the client and the server which helps 
in the handshake procedure to establish a secure encrypted and trusted communication channel
***********************************************************************************************/
#include "headers.h"
#include "handshakeHelper.h"
#include "genericHelper.h"

/* Name of the file containing the CA certificate */
const char * CACertFile = "cacert.pem";


/******************************************************************************************
Function: extractPublicKeyFromCert()
Description: Extracts and return the public key in a character buffer from the X509 structure
of the certificate received as as input. It also sets the length of the public key extracted.
******************************************************************************************/
unsigned char * extractPublicKeyFromCert(X509 * cert, int * clientPublicKeyLength)
{ 
	EVP_PKEY * pkey;
        if((pkey = X509_get_pubkey(cert)) == NULL)
        {
                fprintf(stderr, "Error in extracting public key from the certificate.\n");
                return NULL;
        }
	unsigned char *ucBuf, *uctempBuf;
	* clientPublicKeyLength = i2d_PublicKey(pkey, NULL);
	ucBuf = (unsigned char *)malloc((*clientPublicKeyLength)+1);
	uctempBuf = ucBuf;
	i2d_PublicKey(pkey, &uctempBuf);
	return ucBuf;
}


/******************************************************************************************
Function: readCACertInX509()
Description: Reads the CA certifcate from the file whose name is passed as input and returns
the certificate in X509 format
******************************************************************************************/
X509 * readCACertInX509()
{
	FILE * fp = fopen(CACertFile, "r");
        if(!fp)
        {
                fprintf(stderr, "unable to open file %s \n", CACertFile);
                exit(1);
        }
        X509 * CACert = PEM_read_X509(fp, NULL, NULL, NULL);
        if(!CACert)
        {
                fprintf(stderr, "Failed to parse certificate in %s\n", CACertFile);
                fclose(fp);
                exit(1);
        }
	fclose(fp);
	return CACert;
}


/******************************************************************************************
Function: PEMToX509()
Description: Converts the certificate from a raw character string format to X509 structure
******************************************************************************************/
X509 * PEMToX509(char *pem)
{
    X509 *cert = NULL;
    BIO *bio = NULL;
    if (!pem) {
        fprintf(stderr, "The PEM char string containing server certificate is NULL.\n");
        exit(1);
    }
    bio = BIO_new_mem_buf(pem, strlen(pem));
    if (NULL == bio) {
        return NULL;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}


/******************************************************************************************
Function: generateSessionKey()
Description: Generates a 128-bit session key by computing the MD5 hash of the two random 
keys received
******************************************************************************************/
unsigned char * generateSessionKey(unsigned char * randomKeyOne, unsigned char * randomKeyTwo)
{
	EVP_MD_CTX *mdctx;
 	const EVP_MD *md;
	unsigned char * md_value = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
	unsigned int md_len;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("md5");
	if(!md)
	{
		printf("Unknown message digest.\n");
		exit(1);
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, randomKeyOne, KEY_SIZE_IN_BYTES);
	EVP_DigestUpdate(mdctx, randomKeyTwo, KEY_SIZE_IN_BYTES);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	return md_value;
	 //EVP_cleanup();
	 //exit(0);
}


/******************************************************************************************
Function: readCertInPEM()
Description: read the certificate from a file to a character buffer
******************************************************************************************/
char * readCertInPEM(const char * certFile, int * len)
{
        FILE * fp = fopen(certFile, "r");
        if(!fp)
        {
                fprintf(stderr, "unable to open file %s \n", certFile);
                exit(1);
        }
        X509 * cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if(!cert)
        {
                fprintf(stderr, "Failed to parse certificate in %s\n", certFile);
                fclose(fp);
                exit(1);
        }
        fclose(fp);
        BIO *bio = NULL;
        char *pem = NULL;
        bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
                fprintf(stderr, "Failed to initialize bio.\n");
                exit(1);
        }
        if (0 == PEM_write_bio_X509(bio, cert))
        {
                BIO_free(bio);
                fprintf(stderr, "Failed in PEM_write_bio_X509()\n");
                exit(1);
        }
	  pem = (char *) malloc(bio->num_write + 1);
        if (!pem)
        {
                BIO_free(bio);
                fprintf(stderr, "Failed to malloc memory for pem.\n");
                exit(1);
        }
        memset(pem, 0, bio->num_write + 1);
        BIO_read(bio, pem, bio->num_write);
        BIO_free(bio);
        printf("Cert: \n%s\n", pem);
        *len = bio->num_write+1;
        printf("Len: %d\n", *len);
        return pem;
}


/******************************************************************************************
Function: verifyCert()
Description: verify that the candidate certificate has been signed by the trusted CA 
x509_check_issued() function available in openssl has been used for the verification purpose.
******************************************************************************************/
int verifyCert(X509 * CACert, X509 * testCert)
{
	if(X509_check_issued(CACert, testCert) == X509_V_OK)
               return 1;
        else
               return 0;
}


/******************************************************************************************
Function: encryptRandomKey()
Description: Generates a random key and encrypts it with the public key extracted from the
certificate received from the other party
******************************************************************************************/
unsigned char * encryptRandomKey(X509 * cert, int * lengthOfEncryptedRandomKey,  unsigned char ** randomKey)
{
        unsigned char * encryptedRandomKey;
        EVP_PKEY * pkey;
        if((pkey = X509_get_pubkey(cert)) == NULL)
        {
                fprintf(stderr, "Error in extracting public key from the certificate.\n");
                return NULL;
        }
        //printf("Type: %d\n", pkey->type);
        *randomKey = (unsigned char *)malloc(KEY_SIZE_IN_BYTES+1);
        memset(*randomKey, 0, KEY_SIZE_IN_BYTES+1);
        //RAND_load_file("/dev/urandom", 20);
        int rc = RAND_bytes(*randomKey, KEY_SIZE_IN_BYTES);
        if(rc != 1)
        {
                fprintf(stderr, "RAND_bytes() failed.\n");
        }
        //print_hex((const char *)randomKey, KEY_SIZE_IN_BYTES);
        EVP_PKEY_CTX *ctx;
        size_t outlen;
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx)
        {
                fprintf(stderr, "Error in EVP_PKEY_CTX_new()\n");
                return NULL;
        }
        if (EVP_PKEY_encrypt_init(ctx) <= 0)
        {
                fprintf(stderr, "Error in EVP_PKEY_encrypt_init()\n");
                return NULL;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        {
                fprintf(stderr, "Error in EVP_PKEY_CTX_set_rsa_padding()\n");
                return NULL;
        }
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, *randomKey, KEY_SIZE_IN_BYTES) <= 0)
        {
                fprintf(stderr, "Error in EVP_PKEY_encrypt() while determining outlen. \n");
                return NULL;
        }
        encryptedRandomKey = (unsigned char *)OPENSSL_malloc(outlen);
	if (!encryptedRandomKey)
        {
                fprintf(stderr, "Failed while allocing memory for encrytedRandomKey.\n");
                return NULL;
        }
        if (EVP_PKEY_encrypt(ctx, encryptedRandomKey, &outlen, *randomKey, KEY_SIZE_IN_BYTES) <= 0)
        {
                fprintf(stderr, "Error in EVP_PKEY_encrypt()\n");
                return NULL;
        }
        * lengthOfEncryptedRandomKey = outlen;
        return encryptedRandomKey;
}


/******************************************************************************************
Function: decryptRandomKey()
Description: Extracts the random key from the cipher text by decrypting it using the private
key of this party
******************************************************************************************/
unsigned char * decryptRandomKey(const char * privateKeyFile, unsigned char * in, size_t inlen, int * lengthOfDecryptedRandomKey)
{
	EVP_PKEY_CTX *ctx;
	unsigned char *out;
 	size_t outlen;
	FILE * fp = fopen(privateKeyFile, "r");
 	EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	ctx = EVP_PKEY_CTX_new(key, NULL);
 	if (!ctx)
        {
		fprintf(stderr, "Error in EVP_PKEY_CTX_new()\n");
		return NULL;
	}
	if (EVP_PKEY_decrypt_init(ctx) <= 0)
        {
                fprintf(stderr, "Error in EVP_PKEY_decrypt_init()\n");
                return NULL;
        }
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
	{
                fprintf(stderr, "Error in EVP_PKEY_CTX_set_rsa_padding()\n");
                return NULL;
        }
 	if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
        {
		fprintf(stderr, "Error in EVP_PKEY_decrpyt() while determining outlen.\n");
                return NULL;
	}
	out = (unsigned char *)OPENSSL_malloc(outlen);
	if (!out)
        {
		fprintf(stderr, "Error while allocating memory.\n");
		return NULL;
	}
	if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
        {
		fprintf(stderr, "Error in EVP_PKEY_decrpyt().\n");
		return NULL;
	}
	* lengthOfDecryptedRandomKey = outlen;
	fclose(fp);
	return out;
}

/**********************************************EOF*********************************************/
