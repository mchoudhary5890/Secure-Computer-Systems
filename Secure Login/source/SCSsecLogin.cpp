/*****************************************************************
Program: Secure Login Service (2 Factor Authentication System)
Design Reference: Password hardening based on keystroke dynamics, Monrose et. al.

*****************************************************************/

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<openssl/bn.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>
#include<openssl/aes.h>
#include<iomanip>
#include<openssl/err.h>
#include<openssl/conf.h>
#include<iostream>
#include<string>
#include<sstream>
#include<algorithm>
#include<math.h>
#include<fstream>
#define FEATURES 15
#define LOGIN_ENTRIES 8
#define POLY_DEGREE 14 

using namespace std;

const unsigned int historySize = 1048; // Constant size for per user history file

int threshold[] = {100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100}; // Threshold values(in ms) for features

float k = 0.5; // System Parameter to provide flexibility and variations in feature values. [0.4, 0.6] is a good range. 



/***********************************************************************
Function: HMACGenerator()
Description: Function to generate HMAC corresponding to the message using 
password as key. SHA1 is the hash function used to compute HMAC.
HMAC function is provided in openssl's crypto library.
************************************************************************/

unsigned char * HMACGenerator(const unsigned char * message, const char * password)
{
	unsigned char * mdVal = (unsigned char *)malloc(21); // SHA1 is of 20 bytes
	if(mdVal == NULL)
	{
		std::cout << "Error while allocating memory in HMACGenerator.\n";
		exit(1);
	}
	memset(mdVal, 0, 21);
	unsigned int mdLen;
	HMAC(EVP_sha1(), password, strlen((const char *)password), message, strlen((const char *)message) , mdVal, &mdLen);
	return mdVal;
}

/************************************************************************
Function: strip_newline()
Description: Helper function to remove newline or NULL characters from
the character string passed as argument.
************************************************************************/

int strip_newline(char * str, int size)
{
	for (int i = 0; i < size; i++)
    	{
		if (str[i] == '\n')
        	{
            		str[i] = '\0';
            		return 1;      
		}
    	}
	return 0;
}

/************************************************************************
Function: int_array_to_string()
Description: Helper function to convert the integer array passed as an 
argument to a C++ string
************************************************************************/

string int_array_to_string(int int_array[], int size_of_array) 
{
	std::ostringstream oss;
	for (int temp = 0; temp < size_of_array; temp++)
		if(temp == size_of_array-1)
			oss << int_array[temp] <<'\n';
		else
			oss << int_array[temp] << ' ';
  	return oss.str();
}

/************************************************************************
Function: EVPInitialize()
Description: Function to initialize the EVP encryption/decryption. It is 
a generic function which can be used to initialize any encryption/decryption 
mode. It must be called before calling encrypt/decrypt functions. 
Currently, it takes password and salt to generate the key and IV for 
aes_128_cbc mode. 
EVP is a generic wrapper provided in openssl crypto lib to facilitate a 
single interface to different underlying encryption/decryption modes.
************************************************************************/


int EVPInitialize(unsigned char * password, int passwordLength, unsigned char * salt, EVP_CIPHER_CTX * enCTX, EVP_CIPHER_CTX * deCTX)
{
	int res, numOfRounds = 5;
	unsigned char key[16], iv[16];
	res = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, password, passwordLength, numOfRounds, key, iv);
	if(res != 16)
	{
		std::cout << "Error!! The key size in EVPInitialize is:" << res <<'\n';
		exit(1);
	}
	EVP_CIPHER_CTX_init(enCTX);
	EVP_EncryptInit_ex(enCTX, EVP_aes_128_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(deCTX);
	EVP_DecryptInit_ex(deCTX, EVP_aes_128_cbc(), NULL, key, iv);
	return 0;
} 

/************************************************************************
Function: encrypt()
Description: Function to encrypt the plaintext using the mode, key and IV
set in EVP_CIPHER_CTX via call to EVPInitialize()
************************************************************************/

unsigned char * encrypt(unsigned char * plaintext, int plaintextLength, EVP_CIPHER_CTX *ctx, int *cipherLength)
{
	*cipherLength = plaintextLength + AES_BLOCK_SIZE;
	unsigned char * ciphertext = (unsigned char *)malloc(*cipherLength);
	if(ciphertext == NULL)
	{
		std::cout << "Error in allocating memory for ciphertext in encrypt()" << '\n';
		exit(1);
	}
	memset(ciphertext, 0, *cipherLength);
        int length = 0;
	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate(ctx, ciphertext, cipherLength, plaintext, plaintextLength);
	EVP_EncryptFinal_ex(ctx, ciphertext+(*cipherLength), &length);
	(*cipherLength) += length;
	EVP_CIPHER_CTX_cleanup(ctx); 
	return ciphertext;
}

/************************************************************************
Function: decrypt()
Description: Function to decrypt the ciphertext using the mode, key and IV
set in EVP_CIPHER_CTX via call to EVPInitialize()
************************************************************************/

unsigned char * decrypt(unsigned char * ciphertext, int cipherLength, EVP_CIPHER_CTX * ctx, int * plaintextLength)
{
	int length=0;
	*plaintextLength = cipherLength;
	unsigned char * plaintext = (unsigned char *)malloc(cipherLength);  
	if(plaintext == NULL)
	{
		std::cout<< "Error in allocating memory for plaintext in decrypt()\n";
		exit(1);
	}   
	memset(plaintext, 0, cipherLength);
	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(ctx, plaintext, plaintextLength, ciphertext, cipherLength);
	EVP_DecryptFinal_ex(ctx, plaintext+(*plaintextLength), &length);
	EVP_CIPHER_CTX_cleanup(ctx);
	(*plaintextLength) += length;
	plaintext[*plaintextLength] = '\0';
	return plaintext;
}
/************************************************************************
Function: generateAlphaBeta()
Description: Function to perform following:
	1. Take q, hpwd and password as input
	2. Generate 14 random coefficients in the range(0,q).
	3. Use hpwd and these 14 coefficients to get a polynomial of
	   degree 14.
	4. Generate 15 (X,Y) pairs on the polynomial by setting X = 2i
	   for i [1, 15]
	5. Generate 15 (X,Y) pairs on the polynomial by setting X = 2i+1
	   for i [1, 15] 
	6. Generate 15 Alpha values by adding the Y values from step 4 to
	   the HMAC of corresponding X. (It is a modular operation)
	7. Generate 15 Beta values by adding the Y values from step 5 to 
	   the HMAC of corresponding X. (It is a modular operation)

Openssl's BIGNUM library has been used to maintain all the large numbers 
and to perform modular and arbitrary precision arithmetic 
************************************************************************/


int generateAlphaBeta(BIGNUM * alpha[], BIGNUM * beta[], BIGNUM * q, BIGNUM * hpwd, const char * password)
{
	int result;
 	BIGNUM * coefficients[POLY_DEGREE];
        BIGNUM * yZero[FEATURES]; 
        BIGNUM * yOne[FEATURES];
	for(int i=0; i<POLY_DEGREE; i++)
        {
		coefficients[i] = BN_new();
		result = BN_rand_range(coefficients[i], q);
        }
	for(int i=0; i< FEATURES; i++)
        {
                yZero[i] = BN_new();
                yOne[i] = BN_new();
        }
 
	BIGNUM * twoi = NULL;
	BIGNUM * raiseTo = NULL;
	BIGNUM * twoiPlusOne = NULL;
	BIGNUM * exponentiation = BN_new();
	BIGNUM * mulResult = BN_new();
	for(int i=1; i<= FEATURES; i++)
        {
                BN_CTX * yctx = BN_CTX_new();
                BN_mod_add(yZero[i-1], yZero[i-1], hpwd, q, yctx);
                BN_mod_add(yOne[i-1], yOne[i-1], hpwd, q, yctx);
                for(int j=0; j < POLY_DEGREE; j++)
                {

                        char tempStr[20];
                        snprintf(tempStr, 20, "%d", 2*i);
                        result = BN_dec2bn(&twoi,tempStr);
                        snprintf(tempStr, 20, "%d", j+1);
                        result = BN_dec2bn(&raiseTo, tempStr);
                        snprintf(tempStr, 20, "%d", 2*i+1);
                        BN_dec2bn(&twoiPlusOne, tempStr);
                        BN_CTX * ctx = BN_CTX_new();
                        result = BN_mod_exp(exponentiation, twoi, raiseTo, q, ctx);
                        BN_mod_mul(mulResult, coefficients[j], exponentiation, q, ctx);
                        BN_mod_add(yZero[i-1], yZero[i-1], mulResult, q, ctx);
                        BN_mod_exp(exponentiation, twoiPlusOne, raiseTo, q, ctx);
                        BN_mod_mul(mulResult, coefficients[j], exponentiation, q, ctx);
                        BN_mod_add(yOne[i-1], yOne[i-1], mulResult,q, ctx);
                        BN_CTX_free(ctx);
                }
                BN_CTX_free(yctx);
        }
        BN_clear_free(twoi);
	BN_clear_free(raiseTo);
       	BN_clear_free(twoiPlusOne);
       	BN_clear_free(exponentiation);
       	BN_clear_free(mulResult);

	BIGNUM * keyedHashBN = BN_new();
	BIGNUM * modResult = BN_new();
	for(int i=0; i<FEATURES; i++)
        {
                char tempStr[20];
                snprintf(tempStr, 20, "%d", 2*(i+1));
                unsigned char * keyedHashResult = HMACGenerator((const unsigned char *)tempStr, password);
		BN_dec2bn(&keyedHashBN,(const char *)keyedHashResult);
                BN_CTX *ctx = BN_CTX_new();
                BN_mod(modResult, keyedHashBN, q, ctx);
                BN_mod_add(alpha[i], yZero[i], modResult, q, ctx);
		free(keyedHashResult);
                snprintf(tempStr, 20, "%d", 2*(i+1)+1);
                keyedHashResult = HMACGenerator((const unsigned char *)tempStr, password);
		BN_dec2bn(&keyedHashBN, (const char *)keyedHashResult);
                BN_mod(modResult, keyedHashBN, q, ctx);
                BN_mod_add(beta[i], yOne[i], modResult, q, ctx);
		free(keyedHashResult);
		BN_CTX_free(ctx);
        }
	BN_clear_free(keyedHashBN);
	BN_clear_free(modResult);

	for(int c=0; c<FEATURES; c++)
	{
		BN_clear_free(yZero[c]);
		BN_clear_free(yOne[c]);
	}
	for(int c=0; c< POLY_DEGREE; c++)
 		BN_clear_free(coefficients[c]);
}

/************************************************************************
Function: storeQAlphaBeta()
Description: Function to store the values of q, Alpha[] and Beta[] to a 
file <username>.qab on the disk to maintain to these values for next login
sessions.
The values are stored to the file after converting from the BIGNUM to decimal
************************************************************************/

int storeQAlphaBeta(BIGNUM * q, BIGNUM * alpha[], BIGNUM * beta[], char * uname)
{
	char qabFile[30]={0};
        strncpy(qabFile, uname, strnlen(uname, 20));
        strncat(qabFile, ".", strnlen(".", 5));
        strncat(qabFile, "qab", strnlen("qab", 5));
	FILE * fp;
	fp = fopen(qabFile,"w");
	if(fp == NULL)
	{
		std::cout << "Error in opening qab file in storeQAlphaBeta()\n";
		exit(1);
	}
	fprintf(fp, "%s\n", BN_bn2dec(q));
	for(int i=0; i<FEATURES; i++)
		fprintf(fp, "%s\n", BN_bn2dec(alpha[i]));
	for(int i=0; i<FEATURES; i++)
		fprintf(fp, "%s\n", BN_bn2dec(beta[i]));
	fclose(fp);	
}

/************************************************************************
Function: loadQab()
Description: Function to load the content of the file <username>.qab into
the heap memory of the login process in form of a character string.
************************************************************************/

unsigned char * loadQab(char * username)
{
	char qabFile[30] = {0};
        strncpy(qabFile, username, strnlen(username, 20));
        strncat(qabFile, ".", strnlen(".", 5));
        strncat(qabFile, "qab", strnlen("qab", 5));
        FILE * fp;
	fp = fopen(qabFile,"r");
	if(fp == NULL)
	{
		std::cout << "Error in opening qab file in loadQab().\n";
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	unsigned char * qabData = (unsigned char *)malloc(fsize+1);
	if(qabData == NULL)
	{
		std::cout << "Error in allocation of memory for qabdata in loadQab().\n";
		exit(1);
	}
	fread(qabData, fsize, 1, fp);
	fclose(fp);
	qabData[fsize] = 0;
	return qabData;
}

/************************************************************************
Function: createEncryptedUserHistory()
Description: Function to create a padded and encrypted constant size history 
file "<username>.history" on the disk. This file will always be of the same 
size defined by historySize. This is called only at the time of initialization.
This file is encrypted using a randomly generated hardened password hpwd.
A text string is written to this to ensure the correct file decryption at
the login time.
************************************************************************/

int createEncryptedUserHistory(char * historyFile, BIGNUM * hpwd)
{
	unsigned char * hpwdInDec = (unsigned char *)BN_bn2dec(hpwd); 
	const char * successIdentifier = {"This is history file\n"};
	unsigned char * historyString = (unsigned char *)malloc(historySize+1);
	if(historyString == NULL)
	{
		std::cout << "Error in memory allocation for historyString in createEncryptedUserHistory().\n";
		exit(1);
	}
	memset(historyString, 'x', historySize);
	historyString[historySize] = '\0';
	strncpy((char *)historyString, successIdentifier, strnlen(successIdentifier, 25));
        int fileLength = strnlen((const char *)historyString, historySize+1);
	EVP_CIPHER_CTX enCTX, deCTX;
	unsigned int salt[] = {12345, 54321};
	if(EVPInitialize(hpwdInDec,strlen((const char *)hpwdInDec), (unsigned char *)&salt, &enCTX, &deCTX))
	{
		std::cout << "EVP Initialization failed.\n";
		exit(1);
	}
	int cipherLen = 0;
        unsigned char * cipher = encrypt(historyString, fileLength, &enCTX, &cipherLen);
	FILE *fp;
	fp = fopen(historyFile, "wb");
	if(fp == NULL)
	{
		std::cout << "Error in creating historyFile in createEncryptedUserHistory().\n";
		exit(1);
	}
	fwrite(cipher, cipherLen, 1, fp);
	fclose(fp);
}

/************************************************************************
Function: encryptAndStoreUserHistory()
Description: Function to overwrite the already existing history file
with the updated and encryted user history. The user history is padded
to ensure that the stored file is always of the same length.
************************************************************************/

int encryptAndStoreUserHistory(char * historyFile, BIGNUM * hpwd, unsigned char * userHistory)
{
        unsigned char * hpwdInDec = (unsigned char *)BN_bn2dec(hpwd);
        int fileLength = strnlen((const char *)userHistory, historySize+1);
        EVP_CIPHER_CTX enCTX, deCTX;
        unsigned int salt[] = {12345, 54321};
        if(EVPInitialize(hpwdInDec,strlen((const char *)hpwdInDec), (unsigned char *)&salt, &enCTX, &deCTX))
        {
                std::cout << "EVP Initialization failed.\n";
                exit(1);
        }
        int cipherLen = 0;
        unsigned char * cipher = encrypt(userHistory, fileLength, &enCTX, &cipherLen);
        FILE *fp;
        fp = fopen(historyFile, "wb");
	if(fp == NULL)
	{
		std::cout << "Error in opening history file in encryptAndStoreUserHistory().\n";
		exit(1);
	}
        fwrite(cipher, cipherLen, 1, fp);
        fclose(fp);
}

/************************************************************************
Function: decryptUserHistory()
Description: Function to read the content of the user history file stored
on the disk into a char string. This cipher string is then decrypted to 
recovered the user history which will have max 8 lists of feature values
corresponding to the last 8 successful logins along with string to verify
correct decryption and padding.
************************************************************************/

unsigned char * decryptUserHistory(char * historyFile, BIGNUM * hpwd)
{
	unsigned char * hpwdInDec = (unsigned char *)BN_bn2dec(hpwd);
	int plainLen = 0;
	EVP_CIPHER_CTX deCTX, enCTX;
	FILE * fp;
	fp = fopen(historyFile,"rb");
	if(fp == NULL)
	{
		std::cout << "Error opening history file in decryptUserHistory().\n";
	}
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	unsigned char * cipherRead = (unsigned char *)malloc(fsize+1);
	if(cipherRead == NULL)
	{
		std::cout << "Error in memory allocation for cipher in decryptUserHistory().\n";
		exit(1);
	}
	fread(cipherRead, fsize, 1, fp);
	fclose(fp);
	cipherRead[fsize] = 0;
	unsigned int salt[] = {12345, 54321};
	if(EVPInitialize(hpwdInDec, strlen((const char *)hpwdInDec), (unsigned char *)&salt, &enCTX, &deCTX))
        {
                std::cout << "EVP Initialization failed.\n";
                exit(1);
        }
        unsigned char * recoveredUserHistory = decrypt(cipherRead, fsize, &deCTX, &plainLen);
	return recoveredUserHistory; 
}

/************************************************************************
Function: registerAndInitialize()
Description: Function to be called once to register each new user.
Registration includes generation of hardened password and q for the user 
as well as creation of encrypted binary history file with no feature values 
initially. In addition, alpha and beta values are generated using user
supplied password  which are stored on the disk for future login verfication.
************************************************************************/

int registerAndInitialize(char * historyFile, char * newPassword, char * uname)
{
	BIGNUM * q = BN_new();
	BIGNUM * hpwd = BN_new();
	q = BN_generate_prime(NULL, 160, 1, NULL, NULL, NULL, NULL);
	BN_rand_range(hpwd, q);
	//printf("\nOriginal hpwd: %s \n", BN_bn2dec(hpwd));
	BIGNUM * alpha[FEATURES];
	BIGNUM * beta[FEATURES];
	for(int i=0; i< FEATURES; i++)
	{
		alpha[i] = BN_new();
		beta[i] = BN_new();
	}
	generateAlphaBeta(alpha, beta, q, hpwd, (const char *)newPassword);
	storeQAlphaBeta(q, alpha, beta, uname);
	createEncryptedUserHistory(historyFile, hpwd);
	BN_clear_free(q);
	BN_clear_free(hpwd);
	for(int c=0; c<FEATURES; c++)
	{
		BN_clear_free(alpha[c]);
		BN_clear_free(beta[c]);
	}
	return 0;
}

/************************************************************************
Function: generateXY()
Description: Function to recover 15 (X,Y) pairs using Alpha[] and Beta[].
The choice of Alpha and Beta as well as X value depends on the input
feature values for the current login as explained in the reference paper.
************************************************************************/


int generateXY(BIGNUM * alpha[], BIGNUM * beta [], BIGNUM * xValues[], BIGNUM * yValues[], BIGNUM * q, int inPhi[], const char * inPassword)
{
	unsigned char * keyedHashResult = NULL;
	BIGNUM * keyedHashBN = NULL;
	BIGNUM * modResult = BN_new();
        BN_CTX * ctx = BN_CTX_new();

	for(int i=0; i<FEATURES; i++)
	{
		if(inPhi[i] < threshold[i])
		{
			char tempStr[20];
                	snprintf(tempStr, 20, "%d", 2*(i+1));
			keyedHashResult = HMACGenerator((const unsigned char *)tempStr, inPassword);
                	BN_dec2bn(&keyedHashBN, (const char *)keyedHashResult);
			BN_mod(modResult, keyedHashBN, q, ctx);
			BN_mod_sub(yValues[i], alpha[i], modResult, q, ctx);
			BN_dec2bn(&xValues[i], (const char *)tempStr);
			free(keyedHashResult);
		}
		else
		{
			char tempStr[20];
                        snprintf(tempStr, 20, "%d", 2*(i+1)+1);
                        keyedHashResult = HMACGenerator((const unsigned char *)tempStr, inPassword);
                        BN_dec2bn(&keyedHashBN, (const char *)keyedHashResult);
			BN_mod(modResult, keyedHashBN, q, ctx);
                        BN_mod_sub(yValues[i], beta[i], modResult, q, ctx);
                        BN_dec2bn(&xValues[i], (const char *)tempStr);
			free(keyedHashResult);
		}
	}		
	BN_CTX_free(ctx);
	BN_clear_free(keyedHashBN);
	BN_clear_free(modResult);
}

/************************************************************************
Function: recoverHpwd()
Description: Function to recover the hardened password using the 15 (X,Y)
pairs recovered. Lagrange interpolation (as explained in the paper) is 
used to recover the hardened password.
************************************************************************/


int recoverHpwd(BIGNUM * xValues[], BIGNUM * yValues[], BIGNUM * q, BIGNUM * recoveredHpwd)
{
	BIGNUM * subResult = BN_new();
	BIGNUM * invResult = BN_new();
	BIGNUM * mulResult = BN_new();
	BIGNUM * yLambdaMulResult = BN_new();
	BN_CTX * ctx = BN_CTX_new();
	BN_zero(recoveredHpwd);
	for(int i=0; i<FEATURES; i++)
	{
		BIGNUM * lambda = BN_new();
		BN_one(lambda);
		for(int j=0; j<FEATURES; j++)
		{
			if(i==j)
				continue;
			BN_mod_sub(subResult, xValues[j], xValues[i], q, ctx);
			BN_mod_inverse(invResult, subResult, q, ctx);
			BN_mod_mul(mulResult, xValues[j], invResult, q, ctx);
			BN_mod_mul(lambda, lambda, mulResult, q, ctx);	
		}
		BN_mod_mul(yLambdaMulResult, yValues[i], lambda, q, ctx);
		BN_mod_add(recoveredHpwd, recoveredHpwd, yLambdaMulResult, q, ctx);
		BN_clear_free(lambda);
	}	
	BN_clear_free(subResult);
	BN_clear_free(invResult);
	BN_clear_free(mulResult);
	BN_clear_free(yLambdaMulResult);
	BN_CTX_free(ctx);
}

/************************************************************************
Function: computeMeanAndVarianceOfUserHistory()
Description: Helper Function to compute mean and standard deviation for
each feature using the 8 lists of feature values present in the user 
history.  
************************************************************************/


int computeMeanAndVarianceOfUserHistory(std::string cppHistoryString, float mean[], float deviation[], int debugMode)
{
	std::istringstream iss(cppHistoryString);
	std::string token;
	string featureVectors[LOGIN_ENTRIES];
	int counter = 0;
	while(getline(iss, token, '\n'))
	{
		if((token.find("history")!= std::string::npos) || (token.find('x') != std::string::npos))
			continue;
		else
			featureVectors[counter++] = token;
	}
	int featureValues[LOGIN_ENTRIES][FEATURES];
	for(int i=0; i < LOGIN_ENTRIES; i++)
	{
		counter = 0;
		std::istringstream iss(featureVectors[i]);
		while(getline(iss, token, ' '))
			featureValues[i][counter++] = atoi(token.c_str());

	}
	for(int j=0; j < FEATURES; j++)
	{
		float sum = 0.0;	
		for(int i=0; i<8; i++)
			sum += featureValues[i][j];
		mean[j] = sum/8.0;
		if(debugMode)
			cout << "Mean for " << j << ": " << mean[j] << "\n";
	}
	for(int j=0; j<FEATURES; j++)
	{
		float variance = 0.0;
		for(int i=0;i<8; i++)
			variance += ((featureValues[i][j]-mean[j])*(featureValues[i][j] - mean[j]));
		deviation[j] = sqrt(variance/8);	
		if(debugMode)
			cout << "deviation for "<< j << ": " << deviation[j] << "\n";
	}	 				

}

/************************************************************************
Function: randomizeAlphaBeta()
Description: Function to insert radom values in Alpha[] and beta[] for
the distinguishing features using the criteria explained in the class.
Correct values are maintained for Alpha and Beta correpsonding to non-
distinguishing features
************************************************************************/

int randomizeAlphaBeta(BIGNUM * q, BIGNUM * alpha[], BIGNUM * beta[], float mean[], float deviation[])
{
	for(int i =0; i< FEATURES; i++)
	{
		if(fabsf(mean[i]-threshold[i]) > (k*deviation[i]))
		{
			if(mean[i] < threshold[i])
				BN_rand_range(beta[i], q);
			else if(mean[i] >= threshold[i])
				BN_rand_range(alpha[i],q);
		}
	}
}	

/************************************************************************
Function: updateInstructonTable()
Description: Function to update the instruction table after each successful
login attempt. It does following:
	1. Use the same q and recovered hpwd to generate a new polynomial
	   and new values for alpha[] and beta[]
	2. If the user history has 8 entries for the feature values 
	   corresponding to the last 8 successful login attempts, compute
	   the mean and variance for each feature and randomize the 
	   alpha[] and beta[] values accordingly.
	3. Store the new alpha[] and beta[] values along with q to disk.
************************************************************************/


int updateInstructionTable(BIGNUM * q, BIGNUM * recoveredHpwd, std::string cppHistoryString, char * password, char * uname, int debugMode)
{
	BIGNUM * alpha[FEATURES];
        BIGNUM * beta[FEATURES];
        for(int i=0; i< FEATURES; i++)
        {
                alpha[i] = BN_new();
                beta[i] = BN_new();
        }
        generateAlphaBeta(alpha, beta, q, recoveredHpwd, (const char *)password);
	size_t numNewLines = std::count(cppHistoryString.begin(), cppHistoryString.end(), '\n');
	if(numNewLines >= 9)
        {
                float mean[FEATURES], deviation[FEATURES];
                computeMeanAndVarianceOfUserHistory(cppHistoryString, mean, deviation, debugMode);
                randomizeAlphaBeta(q, alpha, beta, mean, deviation);
        }	
        storeQAlphaBeta(q, alpha, beta, uname);
	for(int c=0; c<FEATURES; c++)
	{
		BN_clear_free(alpha[c]);
		BN_clear_free(beta[c]);
	}
}

/************************************************************************
Function: postAuthenticationManager()
Description: Function to execute following operations after each
successful login attempt:
	1. Insert the new feature values corresponding th current login
	   into the user history.
	2. Ensure the the update history has the predefined constant size.
	3. Generate a new hardened password
	4. Encrypt and store the user history to the disk.
	5. Update the instruction table (call to updateInstructionTable())
************************************************************************/

int postAuthenticationManager(BIGNUM * q, BIGNUM * recoveredHpwd, char * recoveredUserHistory, int inPhi[], char * historyFile, char * password, char * uname, int debugMode)
{
	string fvString = int_array_to_string(inPhi, FEATURES);
	std::string cppHistoryString = recoveredUserHistory;
	size_t numNewLines = std::count(cppHistoryString.begin(), cppHistoryString.end(), '\n');
	if(numNewLines < 9)
	{ 
		std::size_t index =  cppHistoryString.find('x');
        	cppHistoryString.replace(index, fvString.size(), fvString);
	}
	else
	{
		int firstNewLine = cppHistoryString.find('\n');	
		int secondNewLine = cppHistoryString.find('\n', firstNewLine+1);
		cppHistoryString.erase(firstNewLine+1, secondNewLine-firstNewLine);
		std::size_t index =  cppHistoryString.find('x');
		cppHistoryString.replace(index, fvString.size(), fvString); 
	}
      	cppHistoryString.resize(historySize, 'x');
	if(debugMode)
        	cout << "Size of String: " << cppHistoryString.size() << '\n';
	unsigned char * userHistory =(unsigned char *) cppHistoryString.c_str();
	if(debugMode)
		std::cout << "User history to be stored: \n"<< userHistory << '\n';
	BIGNUM * newHpwd = BN_new();
	BN_rand_range(newHpwd, q);
	encryptAndStoreUserHistory(historyFile, newHpwd, userHistory);
	updateInstructionTable(q, newHpwd, cppHistoryString, password, uname, debugMode);
	BN_clear_free(newHpwd);
}

/************************************************************************
Function: authenticateLoginRequest()
Description: Function to autheticate the login request in following way:
	1. Read the values for q, alpha[] and beta[] from the qab file
	2. Recover 15 (X,Y) pairs by calling generateXY()
	3. Recover hpwd' by calling recoverHpwd()
	4. Decrypt the user's history file using hpwd'
	5. Verify the decrytion by searching for the success identifier
	6. Call postAuthenticationManager() to perform post login operations
	   which will help to authenticate next login attempt.
************************************************************************/


int authenticateLoginRequest(char * username, char * inPassword, int inPhi[], char * historyFile, int debugMode)
{
	const char * successIdentifier = {"This is history file\n"};
	BIGNUM * q = BN_new();
	BIGNUM * alpha[FEATURES];
        BIGNUM * beta[FEATURES];
	BIGNUM * xValues[FEATURES];
	BIGNUM * yValues[FEATURES];
        for(int i=0; i< FEATURES; i++)
        {
                alpha[i] = BN_new();
                beta[i] = BN_new();
		xValues[i] = BN_new();
		yValues[i] = BN_new();
        }
	unsigned char * qabData = loadQab(username);
	std::string cppQabData = (char *)qabData;
        std::istringstream iss(cppQabData);
        std::string qabStringList[31];
	std::string token;
        int counter = 0;
        while(getline(iss, token, '\n'))
		qabStringList[counter++] = token;
	BN_dec2bn(&q, (const char *)qabStringList[0].c_str());
	for(int i=1; i < 16; i++)
		BN_dec2bn(&alpha[i-1], (const char *)qabStringList[i].c_str());
	for(int i=16; i < 31; i++)
                BN_dec2bn(&beta[i-16], (const char *)qabStringList[i].c_str());
	generateXY(alpha, beta, xValues, yValues, q, inPhi, (const char *)inPassword);
	BIGNUM * recoveredHpwd = BN_new();
	recoverHpwd(xValues, yValues, q, recoveredHpwd);
	if(debugMode)
		std::cout << "\nRecovered hpwd: " <<  BN_bn2dec(recoveredHpwd) << '\n';
	unsigned char * recoveredUserHistory = decryptUserHistory(historyFile, recoveredHpwd);
        if(debugMode)
		std::cout << "\nRecovered: \n" << recoveredUserHistory << '\n';
	if(strstr((const char *)recoveredUserHistory, (const char *)successIdentifier) == NULL)
		std::cout << "Authentication Failed :(\n";
	else
	{
		std::cout << "Authenticated Successfully!! :)\n";
		postAuthenticationManager(q, recoveredHpwd, (char *)recoveredUserHistory, inPhi, historyFile, inPassword, username, debugMode);
	}
	BN_clear_free(q);
	BN_clear_free(recoveredHpwd);
	for(int c=0; c<FEATURES; c++)
	{
		BN_clear_free(alpha[c]);
		BN_clear_free(beta[c]);
		BN_clear_free(xValues[c]);
		BN_clear_free(yValues[c]);
	}
} 

/************************************************************************
Function: main()
Description: Main Function to execute following operations:
	1. Take username as input.
	2. Check whether the user is registered or not.
	3. If no, ask if user wants to register, get the password and call
	   registerAndInitialize()
	4. If yes, get the password and ask if user want it to run in test
	   mode.
	5. If no, take the feature values for current login as input and 
	   call authenticateLoginRequest()
	6. If yes, take the sample file name as input, extract the lists
	   of feature values from the file and call authenticateLogin()
	   for each entry.
************************************************************************/


int main(int argc, char * argv[])
{
	char uname[20] = {0};
	printf("Username(Max 18 characters):\n");
	if(fgets(uname, 20, stdin)== NULL)
	{
		std::cout << "Wrong Input.\n";
		exit(0);
	}
	if(strip_newline(uname, 20) != 1)	
	{
                std::cout << "Wrong Input. Did you exceed the limit.\n";
                exit(0);
        }
	char historyFile[30] = {0};
	strncpy(historyFile, uname, strnlen(uname, 20));
	strncat(historyFile, ".", strnlen(".", 5));
	strncat(historyFile, "history", strnlen("history", 10));
	if(access(historyFile, F_OK) == -1)
	{
		std::cout << "Username not registered!! Wanna Register Now?(1/0 for Yes/No) \n";
		int userChoice = 0; 
		char choiceString[5];
		if(fgets(choiceString, sizeof(choiceString), stdin) == NULL)
		{
			std::cout << "Error in parsing user choice input.\n";
			exit(1);
		}
		if(strip_newline(choiceString, 5) != 1)
	        {
        	        std::cout << "Wrong Input. Did you exceed the limit.\n";
               		exit(0);
      	  	}
		userChoice = atoi(choiceString);
		if(userChoice != 1)
		{
			std::cout << "Have a good day!!\n";
			exit(0);
		}
		std::cout << "Password: (Use 'passw0rd')\n";
        	char newPassword[20];
        	if(fgets(newPassword, 20, stdin) == NULL)
		{
			std::cout << "Wrong Input.\n";
			exit(0);
		}
        	if(strip_newline(newPassword, 20) != 1)
		{
                        std::cout << "Wrong Input. Did you exceed the limit.\n";
                        exit(0);
                }
		registerAndInitialize(historyFile, newPassword, uname);
		std::cout << "\nRegistered Successfully!!\n";
		return 0;
	}
	std::cout << "Password: (Use 'passw0rd')\n";
	char inPassword[20];
	if(fgets(inPassword, 20, stdin) == NULL)
	{
		std::cout << "Wrong Input.\n";
		exit(0);
	}
	if(strip_newline(inPassword, 20) != 1)
	{
                std::cout << "Wrong Input. Did you exceed the limit.\n";
                exit(0);
        }
	std::cout << "Do you want the service to run in test mode?(1/0 for Yes/No)\n";
	int userChoice = 0;
        char choiceString[5] = {0};
	if(fgets(choiceString, sizeof(choiceString), stdin) == NULL)
	{
		std::cout << "Error in parsing user choice input.\n";
		exit(0);
	}
	if(strip_newline(choiceString, 5) != 1)
        {
		std::cout << "Wrong Input. Did you exceed the limit.\n";
                exit(0);
        }
	userChoice = atoi(choiceString);
	if(userChoice == 0)
	{
		std::cout << "Feature Values:\n";
		int inPhi[FEATURES];
		for (int i=0; i<FEATURES; i++)
			scanf("%d", &inPhi[i]);
		authenticateLoginRequest(uname, inPassword, inPhi, historyFile, 0);
		EVP_cleanup();
	}
	else if(userChoice == 1)
	{
		char sampleFile[20] = {0};
		std::cout << "Running in test mode. Enter sample file name(Max 18 characters).\n";
		if(fgets(sampleFile, 20, stdin) == NULL)
		{
			std::cout << "Wrong Input.\n";
			exit(0);
		}
		if(strip_newline(sampleFile, 20) != 1)
		{
                	std::cout << "Wrong Input. Did you exceed the limit.\n";
                	exit(0);
        	}
		std::ifstream infile(sampleFile);
		if(infile.fail())
		{
			std::cout << "Wrong sample file.\n";
			exit(0);
		}
		std::string line;
		std::cout << "Want to enable debug mode?(Intermediate results will be printed)(1/0 for Yes/No)\n";
		int debugMode = 0;
        	char debugString[5] = {0};
        	if(fgets(debugString, sizeof(debugString), stdin) == NULL)
        	{
                	std::cout << "Errror in parsing  debug choice input.\n";
                	exit(0);
        	}
		if(strip_newline(debugString, 5) != 1)
		{
			std::cout << "Wrong Input.\n";
			exit(0);
		}
        	debugMode = atoi(debugString);
		while(std::getline(infile, line))
		{
			std::istringstream iss(line);
			int featureValues[FEATURES];
			for(int i=0; i<FEATURES; i++)
				iss >> featureValues[i];
			authenticateLoginRequest(uname, inPassword, featureValues, historyFile, debugMode);
		}
		EVP_cleanup();
	}
	else
		std::cout << "Sorry, Invalid Choice.\n";
}
/*****************************************EOF********************************************************/
