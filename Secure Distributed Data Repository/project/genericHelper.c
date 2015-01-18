/********************************GENERICHELPER.C************************************************
Module: genericHelper.c
Description: This module provides some generic helper functions to both the client and the server
***********************************************************************************************/
#include "headers.h"
#include "genericHelper.h"

/******************************************************************************************
Function: print_hex()
Description: Prints the data in the received character buffer to the console in hexadecimal 
form.
******************************************************************************************/
void print_hex(const char * s, int size)
{
        int i = 0; 
	for(i=0; i<size; i++)
                printf("%02X ", (unsigned char)s[i]);
        printf("\n");
}


/******************************************************************************************
Function: strip_newline()
Description: Strips the newline from the character buffer also also helps in detecting
buffer overflow scenarios
******************************************************************************************/
int strip_newline(char * str, int size)
{
	int i =0;
	for (i = 0; i < size; i++)
    	{
		if (str[i] == '\n')
        	{
            		str[i] = '\0';
            		return 1;      
		}
    	}
	return 0;
}


/******************************************************************************************
Function: getSubjectFromCert()
Description: Extracts the Common Name from the certificate passed which is used for access
control and delegation purposes
******************************************************************************************/
char * getSubjectFromCert(X509 * cert)
{
	char * subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	char * pattern = "/CN=";
	char * position = strstr(subject, pattern);
	if(!position)
		return NULL;
	char * clientName = (char *)malloc(sizeof(char)*30);
	if(!clientName)
	{
		printf("Memory allocation failed in getSubjectFromCert()\n");
		return NULL;
	}
	memset(clientName, 0, 30);
	strncpy(clientName, position+4, 30);
	return clientName;
}


/******************************************************************************************
Function: readFile()
Description: Read the data from the file with the name passed as input and return the content
of the file and also sets the filesize variable taken as parameter input
******************************************************************************************/
char * readFile(char * filename, long * filesize)
{
	FILE * fp = NULL;
	fp = fopen(filename,"r");
	if(fp == NULL)
	{
		fprintf(stderr, "Error in opening the file %s\n", filename);
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char * fileData = (char *)malloc(fsize+1);
	memset(fileData, 0, fsize+1);
	if(fileData == NULL)
	{
		fprintf(stderr, "Error in allocation of memory to read file: %s\n", filename);
		fclose(fp);
		return NULL;
	}
	fread(fileData, fsize, 1, fp);
	fclose(fp);
	fileData[fsize] = '\0';
	* filesize = fsize;
	return fileData;
}


/******************************************************************************************
Function: getNameWithoutExntension()
Description: Removes the extension from a filename
******************************************************************************************/
char * getNameWithoutExntension(char * mystr) 
{
    	char * retstr = NULL;
    	char * lastdot = NULL;
    	if (mystr == NULL)
        	return NULL;
    	if ((retstr = (char *)malloc(strlen(mystr) + 1)) == NULL)
        	return NULL;
    	strcpy (retstr, mystr);
    		lastdot = strrchr(retstr, '.');
    	if (lastdot != NULL)
        	*lastdot = '\0';
    	return retstr;
}


/******************************************************************************************
Function: getUID()
Description: Function is used to extract the UID from a filename of the format 
<UID>.txt
******************************************************************************************/
void getUID(char * filename, char * UID)
{
	char * baseName = basename(filename);
	strncpy(UID, getNameWithoutExntension(baseName), UIDSIZE);
}


/******************************************************************************************
Function: getPublicKey()
Description: Extracts and returns the public key from the certificate whose filename is 
passed as an input parameter
******************************************************************************************/
EVP_PKEY * getPublicKey(const char * filename)
{
	FILE * fp = fopen(filename, "r");
        if(!fp)
        {
                fprintf(stderr, "unable to open file %s \n", filename);
                return NULL;
        }
        X509 * cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if(!cert)
        {
                fprintf(stderr, "Failed to parse certificate in %s\n", filename);
                fclose(fp);
                return NULL;
        }
	fclose(fp);
	EVP_PKEY * pkey;
        if((pkey = X509_get_pubkey(cert)) == NULL)
        {
                fprintf(stderr, "Error in extracting public key from the certificate.\n");
                return NULL;
        }
	return pkey;
}


/******************************************************************************************
Function: getPrivateKey()
Description: Extracts and returns the private key from the file whose filename is 
passed as an input parameter
******************************************************************************************/
EVP_PKEY * getPrivateKey(const char * filename)
{
	FILE * fp = fopen(filename, "r");
	if(!fp)
        {
                fprintf(stderr, "unable to open file %s \n", filename);
                return NULL;
        }
 	EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if(pkey == NULL)
	{
		fprintf(stderr, "Error in extracting private key.\n");
                return NULL;
        }
	return pkey;
}

/********************************************EOF**********************************************/
