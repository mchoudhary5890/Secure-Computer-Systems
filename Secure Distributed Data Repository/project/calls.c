/*************************************CALLS.C********************************************
Module: calls.c
Description: This module provides the internal functionality and access control for GET, 
PUT and DELEGATE functions
******************************************************************************************/
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <malloc.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <time.h>
#define IV "01234567890123456"

#define MAX_FILE_SIZ_KBS 1
#define FSIZE MAX_FILE_SIZ_KBS*1024*1024


void handleError(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

void hash_func(unsigned char* data,unsigned char* key,unsigned char* ret)
{
    // pass data to be the entered password
    unsigned char* digest;
    int i = 0;
    // Using sha1 hash engine here.
    digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);
    print_hex(digest, 20);
    for(i = 0; i < 20; i++)
         sprintf(&ret[i*2], "%02x", (unsigned char)digest[i]);
}

int read_file(char* filename,char* buf)
{
        FILE* f = NULL;
        long fsize = 0;
        int num =0;

        f = fopen(filename,"rb");
        if(f == NULL)
        {
                printf("No file : %s\n",filename);
                return -1;
        }

        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
//      printf("Size of file to be read: %ld\n",fsize);
        fseek(f, 0, SEEK_SET);

        if(FSIZE - fsize < 1)
        {
                printf("Size of file to be read not supported\n");
                return -1;
        }

        fread(buf, fsize, 1, f);
        //printf("Bytes read: %ld\n",num);
        fclose(f);
        buf[fsize] = 0;

        return fsize+1;
}

int encrypt_sddr(char *plaintext, int plaintext_len, char *key,
  char *iv, char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleError();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleError();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleError();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleError();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt_sddr(char *ciphertext, int ciphertext_len, char *key,
  char *iv, char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleError();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleError();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleError();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleError();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


void init_ID(char* uid)
{
	int res = 1;
	BIGNUM* new_uid = NULL;
        new_uid = BN_new();
        res = BN_generate_prime(new_uid,80,1,NULL,NULL,NULL,NULL);
        if(!res)
        {
                printf("unable to generate uniqueID\n");
                handleError();
        }
	strcpy(uid,BN_bn2dec(new_uid));
	printf("New generated unique ID is: %s \n",uid);
}

void generate_AES_key(char* key)
{
        int res = 1;
        BIGNUM* new_key = NULL;
        new_key = BN_new();
        res = BN_generate_prime(new_key,256,1,NULL,NULL,NULL,NULL);
        if(!res)
        {
                printf("unable to generate uniqueID\n");
                handleError();
        }
        strcpy(key,BN_bn2dec(new_key));
        printf("New generated KEY is: %s \n",key);
}

int get_enc_key(char *ID, char *key)
{
	char name[100] = {'\0'};
        FILE *fp = NULL;
        char s1[1000] = {'\0'};
	char key_enc[256] = {'\0'};
	char *p = NULL;
	
	int i =0;

	sprintf(name, "detail_%s.txt", ID);
        printf("\n\nChecking meta data file :%s\n",name);
        fp = fopen(name, "r");
        if (fp)
        {
		printf("The metadata file exists.. \n");
                /* extract client public key stored in meta data*/
                fgets(s1, 1000, fp);
                for (p = strtok(s1, " "); p!=NULL; p=strtok(NULL, " "))
                {
                        if (3 == i)
                        {
                                strcpy(key_enc,p);
                        }
                        i+=1;
                }

                fclose(fp);
	} 
	else
	{
		printf("Unable to open file\n");
		return 0;
	}
	strcpy (key,key_enc);
	return 1;

}

void get_hex_str_pub_key(int cpkLength, unsigned char *client_pub_key, char *key_extract)
{
	int i = 0;
	char str[2] = {'\0'}; 
	char extract[1024] = {'\0'};	
	for(i=0; i<cpkLength; i++)
	{
        	sprintf(str,"%02X",client_pub_key[i]);
                strcat(extract,str);
        }
	strcpy(key_extract, extract);
	printf("The client key in Hex %s\n",key_extract);
}


/******************************************************************************************
Function: check_match_delegation_file()
Description: Checks if the delegation metadata file exists corresponding to the UID. If yes,
checks whether the requesting client has appropriate delegated rights and the entry is still
valid. In case the client wants to delegate the rights and he is not the owner, propagation 
flag is checked to ensure that he is allowed to propagate the rights.
******************************************************************************************/
int check_match_delegation_file(char *ID, char *clientName, char * requestType, int checkPropagation)
{	
	char fileName[100];
        char line[50] = {0};
	if((clientName == NULL) || (ID == NULL) || (requestType == NULL))
		return 0;
        sprintf(fileName, "delegate_%s.txt", ID); 
	FILE * fp = fopen(fileName, "r");
	if(fp == NULL)
		return 0;
	while (fgets(line, 50, fp) != NULL) 
	{
           	printf("%s\n", line);
		char * storedClientName = strtok(line, " ");
		char * right = strtok(NULL, " ");
		long startTime = atol(strtok(NULL," "));
		long validityPeriod = atol(strtok(NULL, " "));
		int propagationFlag = atoi(strtok(NULL, " "));
		/* Check if the request operation matches the entry */
		if((strcmp("BOTH", right) != 0) && (strcmp(requestType, right) !=0))
		{
			printf("Right didn't match\n");
			continue;		
		}
		/* Check if the clientName matches or if ALL are allowed this operation */
		if ((strcmp("ALL",storedClientName) != 0) && (strcmp(clientName,storedClientName) != 0))
		{
			printf("Client name didn't match\n");	
			continue;
		}
		/* Check if the entry is still valid */
		if ((long)time(NULL) > (startTime + validityPeriod))
		{
			printf("Validity Expired.\n");
			continue;
		}
		/* Check if the propagation flag is set or not */
		if((checkPropagation == 1) && (propagationFlag == 0))
		{
			printf("propagation not allowed.\n");
			continue;
		}
	        printf("Delegation Authenticated!!!\n");
		fclose(fp);	
                return 1;
	}
	fclose(fp);
	return 0;
}

int check_match_meta_data(unsigned char *client_pub_key, int cpkLength, char *ID, char *sec_flag, int choice)
{
	char name[100];
	FILE *fp = NULL;
	char *s1 = NULL;
	char *p = NULL;
	char pub_key[1024];
	char sec_fl[15];
	char key_enc[256];
	char *client_key = NULL;
	int i = 0;
	char *key_extract = NULL;
	long lSize = 0;
        
	/* Check the file named as Detail_ID to check ownership using client_pub_key*/
	sprintf(name, "detail_%s.txt", ID);
	fp = fopen(name, "r");
	if (fp)
	{
		printf("The metadata file exists.. \n");
                fseek (fp , 0 , SEEK_END);
                lSize = ftell (fp);
                rewind (fp);
		s1 = (char *) malloc((lSize)+1);
		if (s1 == NULL) 
		{
			printf ("Memory error\n"); 
			return 0;
		}
                memset(s1, '\0', lSize + 1);
		
			fread(s1, 1, lSize, fp);
			printf("s1:%s\n",s1);
			for (p = strtok(s1, " "); p!=NULL; p=strtok(NULL, " "))
			{
				if (1 == i)
				{
					strcpy(pub_key,p);
				}
			
				if (2 == i)
				{
					strcpy(sec_fl,p);
				}
				if (3 == i)
				{
					strcpy(key_enc,p);
				}
				i+=1;
			}
		
			fclose(fp);
			free(s1);
			printf("The length of the public key is :%lu",strlen(pub_key));
		if (1 == choice) // match public key
		{
			printf("\n \n **Verifying client PUB key..***\n");
			key_extract = (char *) malloc((cpkLength*2)+1);
        		memset(key_extract, '\0', (cpkLength*2)+1);
			get_hex_str_pub_key(cpkLength, client_pub_key, key_extract);
			
			printf("The client key recvd is %s\n",key_extract);	
			printf("pub_key 3::: %s\n",pub_key);
			if (0 == strcmp(key_extract,pub_key))
                        {
                               printf("Public key matched\n");
			       //free(client_key);
				free(key_extract);
                        }
                        else
                        {
                                printf("Public key NOT matched\n");
				//free(client_key);
				free(key_extract);
				return 0;
                        }

		}
		else if (2 == choice) //match sec_flag
		{
			printf("\n\n **Verifying Security_flag..**\n");
			if (0 == strcmp(sec_flag,sec_fl))
                        {
                                printf("Security flag is matched %s\n", sec_fl);                   
                        }
                        else
                        {
                               return 0;
                        }

		}
		else if (3 == choice) //match enc_key
		{
			/*TBD*/
		}
		else
		{
			printf("Invalid match option.. \n");
			return 0;
		}
	}
	else
	{
		printf("Could not read meta data file for ID:%s\n", ID);
		return 0;
	}
	printf("exiting fn check_match_meta_data\n");
	return 1;
}			


/******************************************************************************************
Function: sddr_delegate_file()
Description: Checks if client requesting the delegation is the owner of the file or has
the delegated rights with propagation flag set. If yes, this new delegation rule gets 
entered into the delegation metadata file.
******************************************************************************************/
int sddr_delegate_file(char * ID, unsigned char * client_pub_key, char * delegateToClient, char * clientName, long validityPeriod, char * right, char * propagationFlag, int cpkLength)
{
        char fileName[100] = {0};
        FILE* fp = NULL;
        int ch;
	int i = 0;
	/* Check is the client is authorized to request delegation */
	if ((check_match_meta_data(client_pub_key, cpkLength, ID, NULL, 1) != 1) && (check_match_delegation_file(ID, clientName, right, 1) != 1))
	{
		printf("The user requesting delegation is not eligible\n");	
		return 0;
	}
        sprintf(fileName, "delegate_%s.txt", ID);
        printf("The name is :%s\n",fileName);
	/* Append the delegation rule to the metadata file */
        fp = fopen(fileName, "a");
        if (!fp)
        {
		printf("Error in opening file in sddr_delegate_file().\n");
		return 0;
        }
	fprintf(fp, "%s %s %ld %ld %s\n", delegateToClient, right, (long)time(NULL), validityPeriod*60, propagationFlag);
        fclose(fp);
	return 1;
}


char * sddr_put_file(char * ID, unsigned char * client_pub_key, char * SEC_FLAG,char * buffer, int cpkLength, char *ClientName)
{
	char  * uid = (char *)malloc(80);
	memset(uid, 0, 80);
	char name[100];
	FILE* pFile = NULL;
	FILE* fp = NULL;
	int ch;
        /*use 160 bit key */
	char key[256] = {'\0'};
	char aes_key[256]= {'\0'};
  	/* A 128 bit IV */
	char * retTrue = "true";
	char * retFalse = "false";
  	char *iv = IV;
	char *plaintext = NULL;
        char cipherBuf[FSIZE]= {'\0'};
	char *ciphertext = NULL;
	int ciphertext_len = 0;
	unsigned char passwd[9] = "12345678";
        unsigned char digest[40] = {'\0'};
        unsigned char argc[256] = {'\0'};
        BIGNUM* hashbn = BN_new();
        char sign_key[256]= {'\0'};
        int res = 0;
	char *cpub_key = NULL;
	int i = 0;
	char s1[1000] = {'\0'};
	char *p = NULL;
        char pub_key[1024] = {'\0'};
	char s2[1000] = {'\0'};
	char sec_fl[15] = {'\0'};

	
	printf("Enter sddr_put_file()....\n");
	//strcpy(cpub_key,(client_pub_key));
	//printf("Printing dec value of client_pub_key.. %s\n",cpub_key);
	
	if (0 == strcmp(ID,"NIL"))
	{
		printf("Its a new file.. Generating ID..\n");
		init_ID(uid); // generate new ID for this doc		

		/* Its a new document, so store it as file with the name 
		   same as generated UNIQUE ID and make corresponding detail  
                   file containg relevant info about file*/
		//Check the SEC_FLAG
		if (0 == strcmp(SEC_FLAG,"NONE"))
		{
			strcpy(key,"NONE");
			printf("The key is %s\n", key);  	
			// Create a new file and write buffer contents in it
    			sprintf(name, "%s.txt", uid);
			printf("The name is :%s\n",name);
    			printf("The size of buffer is %lu:",strlen(buffer));
			pFile = fopen(name, "w");
			if (pFile)
			{
        			fwrite(buffer,sizeof(char),strlen(buffer),pFile); 
				fclose(pFile);
    				printf("The buffer looks like: %s\n",buffer); 	
			}	
			else
			{
    				printf("Can't open file\n");
				return retFalse;
			}
		}
		else if (0 == strcmp(SEC_FLAG,"CONFIDENTIAL"))
		{
			/* Generate AES doc encryption key and encrypt it*/	
			generate_AES_key(aes_key);
			printf("The generated AES key is %s:\n",aes_key);
			/* Encrypt the plaintext */
			plaintext = buffer;
			ciphertext = &cipherBuf[0];
			ciphertext_len = encrypt_sddr(plaintext, strlen(plaintext), aes_key, iv, ciphertext);
			/* Do something useful with the ciphertext here */
			 // Create a new file and write encrypted buffer contents in it
                        sprintf(name, "%s.txt", uid);
                        printf("The name is :%s\n",name);
                        pFile = fopen(name, "w");
                        if (pFile)
                        {
                                fwrite(ciphertext,1,ciphertext_len,pFile);
                                printf("The buffer looks like: %s\n",ciphertext);
                                fclose(pFile);
                        }
                        else
                        {
                                printf("Can't open file\n");
                                return retFalse;
                        }
			strcpy(key,aes_key);
			printf("The value of key stored in file after encryption :%s\n",key);	
		}
		else if (0 == strcmp(SEC_FLAG,"INTEGRITY"))
		{	
			sprintf(argc,"%lu",strlen(buffer));
                        hash_func(buffer,passwd,&digest[0]);
                        res = BN_hex2bn(&hashbn,digest);
                        if(!res)
                        {
                                printf("Unable to convert - 2 inst\n");
                                handleError();
                         }
                        strcpy(sign_key,BN_bn2dec(hashbn));                    
                        sprintf(name, "%s.txt", uid);
                        printf("The name is :%s\n",name);
                        pFile = fopen(name, "w");
			if (pFile)
                        {
                                fwrite(buffer,sizeof(char),strlen(buffer),pFile);
				printf("The buffer looks like: %s\n", buffer);
                                fclose(pFile);
                        }
                        else
                        {
                                printf("Can't open file\n");
                                return retFalse;
                        }
                        strcpy(key,sign_key);
                        printf("The value of key stored in file after encryption :%s\n",key);
		}
		else
		{
			printf("SEC_FLAG is invalid\n");
			return retFalse; 
		}
		//write the detail file
		sprintf(name, "detail_%s.txt", uid);
	  	printf("The name is :%s\n",name);	
		fp = fopen(name, "w");
                if (fp)
                {
			fprintf(fp, "%s ",uid);
		        for (i=0; i<cpkLength; i++)
			fprintf(fp, "%02X", client_pub_key[i]);	
			fprintf(fp, "%s"," ");
			fprintf(fp, "%s %s", SEC_FLAG,key);
			fclose(fp); 
                }
                else
                printf("Can't open file\n");
		//read the file
		fp = fopen(name, "r");
		while ((ch = fgetc(fp)) != EOF) 
		{
			putchar(ch); /* print the character */
		}
		fclose(fp);	
		printf("\n\n");
		return uid;      
	}
	else
	{
		if (NULL != ID)
		{
			 printf("Checking if a file with given UID is present.. \n");
			 /* Check if the file is present*/
			 sprintf(name, "%s.txt", ID); 
			 pFile = fopen(name, "r");
			 if(pFile)
			 {
				printf("The file exists.. Continue \n");
				fclose(pFile);						
				/*Check if Client pub key matches the public key
 				stored in file. If matches, check SEC_FLAG */
				if ( (1 == (check_match_meta_data(client_pub_key,cpkLength,ID,NULL,1))) || (1 == (check_match_delegation_file(ID,ClientName, "PUT", 0)))	)
				{
					
					/* Check if the security flag is set as NIL
					   If so, read the meta data file and extract 
					   the sec_flag value*/
					
					if (0 == strcmp(SEC_FLAG,"NIL"))
					{	
						printf("Sec_flag is NIL.. checking metadata..\n");
						//check the security flag in its detail file
                                        	sprintf(name, "detail_%s.txt", ID);
                                        	printf("The name is :%s\n",name);

                                        	i = 0;
                                        	/* Read the file in buffer*/
                                        	fp = fopen(name, "r");
                                        	if (fp)
                                        	{
                                             		printf("The metadata file exists.. \n");
                                                	/* sec_flag stored in meta data*/
                                                	fgets(s2, 1000, fp);
                                                	for (p = strtok(s2, " "); p!=NULL; p=strtok(NULL, " "))
                                                	{
                                                		if (2 == i)
                                                        	{
                                                             		strcpy(sec_fl,p);
                                                       		}
                                                        	i+=1;
                                                	}

                                                	fclose(fp);
                                        	}
                                        	else
                                        	{
                                                	printf("Unable to open MetaDATA file\n");
                                            		return 0;
                                        	}
						strcpy(SEC_FLAG, sec_fl);
						printf("NIL was found. New flag: %s\n", SEC_FLAG);
						
					}

					if (0 == strcmp(SEC_FLAG,"NONE"))
					{
						/* Overwrite the file*/
						pFile = fopen(name, "w");
						if (pFile)
                       				{	
                                			fwrite(buffer,1,sizeof(buffer),pFile);
                                			fclose(pFile);
                                			printf("The buffer looks like: %s\n",buffer);
                        			}
                        			else
                        			{
                                			printf("Can't open file\n");
                                			return retFalse;
                        			}
						//write the detail file
                                                sprintf(name, "detail_%s.txt", ID);
                                                printf("The name is :%s\n",name);

                                                i = 0;
                                                /* Read the file in buffer*/
                                                fp = fopen(name, "r");
                                                if (fp)
                                                {
                                                        printf("The metadata file exists.. \n");
                                                        /* extract client public key stored in meta data*/
                                                        fgets(s1, 1000, fp); 
                                                        for (p = strtok(s1, " "); p!=NULL; p=strtok(NULL, " "))
                                                        {
                                                                if (1 == i)
                                                                {
                                                                        strcpy(pub_key,p);
                                                                }
                                                                i+=1;
                                                        }

                                                        fclose(fp);
                                                }
                                                else
                                                {
                                                        printf("Unable to open MetaDATA file\n");
                                                        return 0;
                                                }
						strcpy(key,"NONE");

                                                /* Now write new metadata*/
						fp = fopen(name, "w");
                                                if (fp)
                                                {
                                                        fprintf(fp, "%s %s %s %s", ID, pub_key, SEC_FLAG, key);
                                                        fclose(fp);
                                                }
                                                else
                                                printf("Can't open file\n");
					}
					else if (0 == strcmp(SEC_FLAG,"CONFIDENTIAL"))
					{
						/* Generate AES doc encryption key and encrypt it*/
			                        generate_AES_key(aes_key);
                        			printf("The generated AES key is %s:\n",aes_key);
			                        /* Encrypt the plaintext */
                        			plaintext = buffer;
                        			ciphertext = &cipherBuf[0];
                        			ciphertext_len = encrypt_sddr(plaintext, strlen(plaintext), aes_key, iv, ciphertext);
                        			/* Do something useful with the ciphertext here */
                         			// Create a new file and write encrypted buffer contents in it
                        			printf("The name is :%s\n",name);
                        			pFile = fopen(name, "w");
                        			if (pFile)
                        			{
                                			fwrite(ciphertext,1,ciphertext_len,pFile);
                                			printf("The buffer looks like: %s\n",ciphertext);
                                			fclose(pFile);
                        			}
                        			else
                        			{
                                			printf("Can't open file\n");
                                			return retFalse;
                        			}
                        			/* aes_key needs to be encrypted with server's
                                		public key before storing it into file. For
                                		now, storing the same aes_key as key; NEEDS
                                		TO BE CHANGED*/
                        			strcpy(key,aes_key);
						/*Store new key in the file*/
                        			printf("The value of key stored in file after encryption :%s\n",key);		
						//write the detail file
                				sprintf(name, "detail_%s.txt", ID);
                				printf("The name is :%s\n",name);
						
						i = 0;	
						/* Read the file in buffer*/
						fp = fopen(name, "r");
						if (fp)
        					{
                					printf("The metadata file exists.. \n");
                					/* extract client public key stored in meta data*/
                					fgets(s1, 1000, fp); 
                					for (p = strtok(s1, " "); p!=NULL; p=strtok(NULL, " "))
                					{
                        					if (1 == i)
                                				{
                                        				strcpy(pub_key,p);
                               					}
                        					i+=1;
                					}

                					fclose(fp);
        					}
						else
						{
                					printf("Unable to open MetaDATA file\n");
                					return 0;
        					}

						/* Now write new AES ey value in metadata*/
                				fp = fopen(name, "w");
                				if (fp)
                				{
                        				fprintf(fp, "%s ",ID);
                        				//for (i=0; i<cpkLength; i++)
                        				//fprintf(fp, "%02X", client_pub_key[i]);
                        				//fprintf(fp, "%s"," ");
                        				fprintf(fp, "%s %s %s", pub_key, SEC_FLAG, key);
                        				fclose(fp);
                				}
                				else
               	 				printf("Can't open file\n");
                				//read the file
                				fp = fopen(name, "r");
                				while ((ch = fgetc(fp)) != EOF)
                				{
                        				putchar(ch); /* print the character */
               					 }
                				fclose(fp);
                				printf("\n\n");
					}
					else if (0 == strcmp(SEC_FLAG,"INTEGRITY"))
					{
						sprintf(argc,"%lu",strlen(buffer));
                        			hash_func(argc,passwd,&digest[0]);
                        			res = BN_hex2bn(&hashbn,digest);
                        			if(!res)
                        			{
                                			printf("Unable to convert - 2 inst\n");
                                			handleError();
                        			}
                        			strcpy(sign_key,BN_bn2dec(hashbn));
                        			printf("The generated sign key is %s:\n",sign_key);
						memset(name, 0, 100);
						sprintf(name, "%s.txt", ID);
                        			printf("The name is :%s\n",name);
                        			pFile = fopen(name, "w");
                        			if (pFile)
                        			{
                                			fwrite(buffer,1,sizeof(buffer),pFile);
                                			fclose(pFile);
                        			}
                        			else
                        			{
                                			printf("Can't open file\n");
                                			return retFalse;
                        			}
                        			strcpy(key,sign_key);
                       	 			printf("The value of key stored in file after encryption :%s\n",key);
                       				//write the detail file
                                                sprintf(name, "detail_%s.txt", ID);
						 i = 0;
                                                /* Read the file in buffer*/
                                                fp = fopen(name, "r");
                                                if (fp)
                                                {
                                                        printf("The metadata file exists.. \n");
                                                        /* extract client public key stored in meta data*/
                                                        fgets(s1, 1000, fp); 
                                                        for (p = strtok(s1, " "); p!=NULL; p=strtok(NULL, " "))
                                                        {
                                                                if (1 == i)
                                                                {
                                                                        strcpy(pub_key,p);
                                                                }
                                                                i+=1;
                                                        }

                                                        fclose(fp);
                                                }
                                                else
                                                {
                                                        printf("Unable to open MetaDATA file\n");
                                                        return 0;
                                                }

                                                printf("The name is :%s\n",name);
                                                fp = fopen(name, "w");
                                                if (fp)
                                                {
                                                        fprintf(fp, "%s ",ID);
                                                        //for (i=0; i<cpkLength; i++)
                                                        //fprintf(fp, "%02X", client_pub_key[i]);
                                                        //fprintf(fp, "%s"," ");
                                                        fprintf(fp, "%s %s %s", pub_key, SEC_FLAG,key);
                                                        fclose(fp);
                                                }
                                                else
                                                printf("Can't open file\n");
                                                fp = fopen(name, "r");
                                                while ((ch = fgetc(fp)) != EOF)
                                                {
                                                        putchar(ch); /* print the character */
                                                 }
                                                fclose(fp);
                                                printf("\n\n"); 		
					}
					else
					{
						printf("Sec_flag Invalid.. \n");
						return retFalse;
					}					
				}
				else
				{
					printf("Client not authorized to access file\n");
					return retFalse;
				}	
			}
			else
			{
				printf("File for the given ID doesn't exist\n");
				return retFalse;
			} 
		}
		else
		{
			printf("ERROR::The ID is NULL!!\n");
			return retFalse;

		}
	}
	return retTrue;
}

char * sddr_get_file(char * ID, unsigned char * client_pub_key, int cpkLength, char *clientName)
{
	FILE *pFile = NULL;
	char name[100] = {'\0'};
	long lSize = 0;
	char * str = NULL;
	char enc_key[256] = {'\0'};
	int decryptedtext_len = 0;
	unsigned char passwd[9] = "12345678";
        unsigned char digest[40] = {'\0'};	
	BIGNUM* hashbn = BN_new();
	char *iv = IV;
	char decryptedtext[2048];
	int res = 0;
	char cipherBuf[FSIZE]= {'\0'};
	memset(cipherBuf, '\0', FSIZE);
	/* Check if the file with this ID exists*/
	printf("Checking if a file with given UID is present.. \n");
        /* Check if the file is present*/
        sprintf(name, "%s.txt", ID);
        pFile = fopen(name, "r");
        if(pFile)
        {
             	printf("The file exists.. Continue \n");
              	fseek (pFile , 0 , SEEK_END);
		lSize = ftell (pFile);
		rewind (pFile);
	      	fclose(pFile);
		printf("The length of the file is :%ld \n",lSize);
	}
	else
	{
		printf("The file with the UID doesn't exist\n");
		return 0;
	}
	/* If exists, check if client public key matches with meta data*/
	if ( (1 == (check_match_meta_data(client_pub_key, cpkLength, ID, NULL, 1)))  || (1 == (check_match_delegation_file(ID,clientName, "GET", 0)))  )
	{
		/* 1. If sec_flag is NONE, simply return the data
		   2. If sec_flag is CONFIDENTIAL, dcrypt it using
		   the key stored in meta data
		   3. If sec_flag is INTEGRITY*/
		printf("Client Authenticated\n");
		// allocate memory to the buffer in which file is read
		str = (char *) malloc(lSize+1);
		if (str == NULL)
		{
			printf("Not enough memory..\n");
			return NULL;
		}
		memset(str, '\0', lSize+1);	
		if (1 == (check_match_meta_data(client_pub_key, cpkLength, ID, "NONE" , 2)))
		{
			pFile = fopen(name, "r");
			if (pFile)
			{
				fread(str, 1, lSize, pFile);
				fclose(pFile);		
			}
			else
			{
				printf("The file with the UID doesn't exist\n");
				free(str);
				return NULL;
			}
			printf("Printing Buffer\n");
			printf("%s\n", str);
		}
		else if (1 == (check_match_meta_data(client_pub_key, cpkLength, ID, "CONFIDENTIAL", 2)))
		{
			get_enc_key(ID, enc_key);	
			res = read_file(name,cipherBuf);
  			if(res < 0)
  			{
        			printf("Issue reading from cipherFile\n");
				free(str);
                                return NULL;		
 			}		
			/*Decrypt using key*/
			 decryptedtext_len = decrypt_sddr(&cipherBuf[0], res-1, enc_key, iv, decryptedtext);
			 /* Add a NULL terminator. We are expecting printable text */
  			decryptedtext[decryptedtext_len] = '\0';
			/* Show the decrypted text */
  			printf("Decrypted history file:\n");
  			printf("%s\n", decryptedtext);
			strcpy(str,decryptedtext);
		}
		else if (1 == (check_match_meta_data(client_pub_key, cpkLength, ID, "INTEGRITY", 2)))
		{
			get_enc_key(ID, enc_key);
                        printf("\nsign_key is %s\n",enc_key);

			pFile = fopen(name, "r");
                        if (pFile)
                        {
                                fread(str, 1, lSize, pFile);
                                fclose(pFile);
                        }
                        else
                        {
                                printf("The file with the UID doesn't exist\n");
                                free(str);
                                return NULL;
                        }
			hash_func(str,passwd,&digest[0]);                        
			res = BN_hex2bn(&hashbn,digest);
                        if(!res)
                        {
                                printf("Unable to convert - 2 inst\n");
                                handleError();
                        }
			printf("key: %s\n", BN_bn2dec(hashbn)); 
			if(strcmp(BN_bn2dec(hashbn), enc_key) != 0)
			{
				printf("The file on the server got corrupted.\n");
				free(str);
				return NULL;
			}
		}
	}
	else
	{
		printf("The client is not authorized to recv ths file\n"); 
		return NULL;	
	}
	/* Check security flag of the file*/
	return str;
}
