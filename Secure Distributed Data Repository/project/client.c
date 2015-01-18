/********************************CLIENT.C*************************************************
Module: client.c
Description: This is the main client module that interact with the user and provides 
different services to the client by communicating with the server in a secure encrypted
session. 
******************************************************************************************/
#include "headers.h"
#include "handshakeHelper.h"
#include "networkHelper.h"
#include "genericHelper.h"

const char * clientCertFile = "client-cert.pem"; 
const char * clientPrivateKeyFile = "client-key.pem";
int sessionEstablished = 0;
const char * servicePort = "5891";

/******************************************************************************************
Function: ssession()
Description: This function establishes a secure session with the server. SSL type handshake
has been implemented to achieve mutual authentication at socket level. The client connects 
to server, recieves server's certificate and verifies it. Then, the client sends its own
certificate to the server. Once the mutual authentication is done, both client and server 
exchange random keys which get hashed at both the ends to generate a random AES 128 bit 
session key. 
******************************************************************************************/
int ssession(char * serverHostname, unsigned char ** sessionKey)
{
	int sockfd;
	int bytesCount;
	struct addrinfo hints, * res, * currentRes;
	int fcallResult;
	char des[INET6_ADDRSTRLEN];
	char buffer[MAXDATASIZE] = {0};
	char * serverPort = (char *)servicePort;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	/* Get server address information in a addrinfo structure */
	if((fcallResult = getaddrinfo(serverHostname, serverPort, &hints, &res)) != 0)
	{
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(fcallResult));
		exit(1);
	}
	for(currentRes=res; currentRes != NULL; currentRes->ai_next)
	{
		/* Create socket using the information from addrinfo structure */
		if((sockfd = socket(currentRes->ai_family, currentRes->ai_socktype, currentRes->ai_protocol)) == -1)
		{
			fprintf(stderr, "socket(): %s\n", strerror(errno));
			continue;
		}
		/* Connect to the server using the socket created */
		if(connect(sockfd, currentRes->ai_addr, currentRes->ai_addrlen) == -1)
		{
			close(sockfd);
			fprintf(stderr, "connect(): %s\n", strerror(errno));
			continue;
		}
		break;
	}
	if(currentRes == NULL)
	{
		fprintf(stderr, "Client failed to connect to the server.\n");
		exit(1);
	}
	inet_ntop(currentRes->ai_family, getInAddr((struct sockaddr *)currentRes->ai_addr), des, sizeof(des));
	printf("Connecting.. %s\n", des);
	freeaddrinfo(res);
	/* Wait for the server certificate */
	if((bytesCount = recv(sockfd, buffer, MAXDATASIZE-1, 0)) == -1)
	{
		fprintf(stderr, "recv(): %s\n", strerror(errno));
		exit(1);
	}
	buffer[bytesCount] = '\0';
	printf("%s\n", buffer);
	X509 * serverCertInX509 = PEMToX509(buffer);
	X509 * CACertInX509 = readCACertInX509();
	/* Verify if the server certificate has been signed by the trusted CA authority */
	if(!verifyCert(CACertInX509, serverCertInX509))
	{
		fprintf(stderr, "Server Cert Verification Failed.\n");
		close(sockfd);
		exit(1);
	}
	printf("Server Certificate Verification Successful.\n");		
	int lengthOfClientCert = 0;
	/* Read the client certificate in a character buffer from the file */
	char * clientCertInPEM = readCertInPEM(clientCertFile, &lengthOfClientCert);
	/* Send the certificate to the server */
	if(send(sockfd, clientCertInPEM, lengthOfClientCert, 0) == -1)
        {
		fprintf(stderr,"send(): %s\n", strerror(errno));
		exit(1);
	}
	/* Wait for a random key from the server */
	if((bytesCount = recv(sockfd, buffer, MAXDATASIZE-1, 0)) == -1)
        {
                fprintf(stderr, "recv(): %s\n", strerror(errno));
                exit(1);
        }
	int lengthOfDecryptedRandomKey;
	/* Decrypt the random key with the private key of this client */
	unsigned char * decryptedRandomKey = decryptRandomKey(clientPrivateKeyFile, (unsigned char *)buffer, (size_t)bytesCount, &lengthOfDecryptedRandomKey);
	if(!decryptedRandomKey)
	{
		fprintf(stderr, "Error While decrypting random key received. \n");
		close(sockfd);
		exit(1);
	}
	int lengthOfEncryptedRandomKey = 0;
	unsigned char * randomKey = NULL;
	unsigned char * encryptedRandomKey = encryptRandomKey(serverCertInX509, &lengthOfEncryptedRandomKey, &randomKey);
	/* Send a random encrypted with the public key of the server*/
	if(send(sockfd, encryptedRandomKey, lengthOfEncryptedRandomKey, 0) == -1)
	{
		fprintf(stderr,"send(): %s\n", strerror(errno));
		exit(1);
	}
	printf("Sent Random Key:\n");
	print_hex((const char *)randomKey, KEY_SIZE_IN_BYTES);
	printf("Received Random Key:\n");
	print_hex((const char *)decryptedRandomKey, lengthOfDecryptedRandomKey);
	/* Generate a session key by hashing both the random keys */
	*sessionKey = generateSessionKey(decryptedRandomKey, randomKey);
	printf("\nSession Key: \n");
	print_hex((const char *)(*sessionKey), KEY_SIZE_IN_BYTES);
	sessionEstablished = 1;
	return sockfd;
}

/******************************************************************************************
Function: writeFile()
Description: function to write the data present in the buffer received from the server on 
a get request to a file corresponding the UID of the file. 
******************************************************************************************/

int writeFile(char * UID, char * data)
{
	char filename[UIDSIZE+5] = {0}; 
	/* Only ".txt" files supported here. It can be easily extended to support different formats */
	sprintf(filename, "%s.txt", UID);
	FILE * fp = NULL;
	fp = fopen(filename, "w");
	if (!fp)
	{
		printf("Error while opening file for write.\n");
		return 0;
	}
	fwrite(data,sizeof(char),strlen(data),fp); 
	fclose(fp);
	return 1; 		
}

/******************************************************************************************
Function: get()
Description: This function forms a request in the following format:
	@GET:<UID>
and sends the request encrypted with the shared session key to the server. On successful
receipt of the file data, it creates a file and writes the data to it. If failed, it 
returns the appropriate value indicating the failure.
******************************************************************************************/
int get(int sockfd, char * UID, unsigned char * sessionKey)
{
	int bytesCount;
	char buffer[MAXDATASIZE] = {0};
	int requestSize = 5 + UIDSIZE + 1;
	/* Calculate the total request size */
	char * request = (char *)malloc(requestSize * sizeof(char));
	if(request == NULL)
	{
		printf("Error in allocating buffer for request.\n");
		return 0;
	}	
	memset(request, '\0', requestSize);
	/* Form the request */
	strncpy(request, "@GET:", 5);
	strncat(request, UID, UIDSIZE);
	printf("The get request is: %s\n", request);
	int cipherLength = 0;
	/* Encrypt the request */
 	unsigned char * encryptedRequest = encrypt(sessionKey, (unsigned char *)request, strlen(request), &cipherLength);
	//print_hex((const char *)encryptedRequest, cipherLength);
	if(encryptedRequest == NULL)
	{
		fprintf(stderr, "Encryption Failed.\n");
		return 0;
	}
	/* Send the encrypted request to the server */
	if(send(sockfd, encryptedRequest, cipherLength, 0) == -1)
        {
		fprintf(stderr,"send(): %s\n", strerror(errno));
		return 0;
	}
	/* Receive the response from the server */
	if((bytesCount = recv(sockfd, buffer, MAXDATASIZE-1, 0)) == -1)
	{
		fprintf(stderr, "recv(): %s\n", strerror(errno));
                return 0;
        }
	int plaintextLength = 0;
	//printf("\nReceived Length:%d\n", bytesCount);
	//printf("Cipher Received:\n");		
	//print_hex(buffer, bytesCount);
	if(bytesCount == 0)
		return 0;
	unsigned char * decryptedResponse = decrypt((unsigned char *)buffer, bytesCount, sessionKey, &plaintextLength);
	if (decryptedResponse == NULL)
	{
		printf("Decryption failed in get.\n");
		return 0;
	}
	//printf("Length: %d\n", plaintextLength);
	printf("Received: %s\n", decryptedResponse);
	if(strcmp(decryptedResponse, "false") == 0)
		return 0;
	/* Write the data to a file */
	else if(!writeFile(UID, decryptedResponse))
		return 0;
	return 1;
}
	
/******************************************************************************************
Function: put()
Description: This function forms a request in the following format:
	@PUT:<Security Flag>:<UID>:<file data> 
and sends the request encrypted with the shared session key to the server. If the file is 
new, it receives a new UID corresponding to this file generated by the server and prints 
on the console. Otherwise, it receives true or false indicating whether the PUT request was 
successful or not. Finally, it return the completion status of the request to the caller.
******************************************************************************************/

int put(int sockfd, char * UID, char * fileData, long fileSize, int securityProperty, unsigned char * sessionKey)
{
	int bytesCount;
	char buffer[MAXDATASIZE] = {0};
	const char * flag = NULL;
	if(securityProperty == 0)
		flag = "NIL";
	else if(securityProperty == 1)
		flag = "NONE";
	else if(securityProperty == 2)
		flag = "CONFIDENTIAL";
	else if(securityProperty == 3)
		flag = "INTEGRITY";
	/* Calculate the request size */
	int requestSize = 5 + strlen(flag) + 1 + UIDSIZE + 1 + fileSize+1;
	char * request = (char *)malloc(requestSize * sizeof(char));
	if(request == NULL)
	{
		printf("Error in allocating buffer for request.\n");
		return 0;
	}
	memset(request, 0, requestSize);
	/* Form the PUT request */
	strncpy(request, "@PUT:", 5);
	strncat(request, flag, strlen(flag));
	strncat(request, ":", 1);
	strncat(request, UID, UIDSIZE);
	strncat(request, ":", 1);
	strncat(request, fileData, fileSize);
	printf("The request is: %s\n", request);
	int cipherLength = 0;
	/* Encrypt the request with the session key */	
	unsigned char * encryptedRequest = encrypt(sessionKey, (unsigned char *)request, strlen(request), &cipherLength);
	if(encryptedRequest == NULL)
	{
		fprintf(stderr, "Encryption Failed in put.\n");
		return 0;
	}
	/* Send the encrypted request to the server */
	if(send(sockfd, encryptedRequest, cipherLength, 0) == -1)
        {
		fprintf(stderr,"send(): %s\n", strerror(errno));
		return 0;
	}
	/* Wait for the response from the server */
	if((bytesCount = recv(sockfd, buffer, MAXDATASIZE-1, 0)) == -1)
	{
		fprintf(stderr, "recv(): %s\n", strerror(errno));
                return 0;
        }
	int plaintextLength = 0;
	//printf("\nReceived Length:%d\n", bytesCount);
	//printf("Cipher Received:\n");		
	//print_hex(buffer, bytesCount);
	if(bytesCount == 0)
		return 0;
	/* Decrypt the response received */
	unsigned char * decryptedResponse = decrypt((unsigned char *)buffer, bytesCount, sessionKey, &plaintextLength);
	if (decryptedResponse == NULL)
	{
		printf("Decryption failed in get.\n");
		return 0;
	}
	//printf("Length: %d\n", plaintextLength);
	printf("Received: %s\n", decryptedResponse);
	if(strcmp(decryptedResponse, "false") == 0)
		return 0;
	/* Print the UID if the uploaded file was new */
	else if(strcmp(UID, "NIL") == 0)
	{
		printf("The new UID generated for your file is: %s\n", decryptedResponse);
		printf("Please store this UID to access this file in future.\n");
	}
	return 1;
}


/******************************************************************************************
Function: endSession()
Description: This function invokes PUT service for each of the file retrieved in this 
session to store them back on the server. After that, it sends a request of the form:
		@TER:
indicating the server that the client wants to terminate the session. Session key gets 
destroyed on return of this function. 
******************************************************************************************/

void endSession(int sockfd, char filesRequested[][UIDSIZE], int numberOfFilesRequested, unsigned char * sessionKey)
{
	int securityProperty = 0;
	/* Invoke PUT service for all the file recieved in this session */
	int i = 0;
	for(i; i<numberOfFilesRequested; i++)
	{
		char * filename = (char *)malloc(UIDSIZE+5);
		if(filename == NULL)
		{
			printf("Error in allocating memory for filename in endSession()\n");
			return;
		}
		memset(filename, 0, UIDSIZE+5);
		strncpy(filename, filesRequested[i], UIDSIZE);
		strncat(filename, ".txt", 4);
		long filesize = 0;
		char * fileData = readFile(filename, &filesize);
		if(fileData == NULL)
		{
			printf("Problem while reading the file in endSession()\n");
			return;
		}
		//printf("Filedata: %s\n", fileData);
		put(sockfd, filesRequested[i], fileData, filesize, securityProperty, sessionKey);
		sleep(3);
	}
	/* The request to be sent to the server */		
	const char * request = "@TER:";		
	printf("The request is: %s\n", request);
	int cipherLength = 0;
	//printf("request size: %zd\n", strlen(request));
	/* Encrypt the request with the session key */
	unsigned char * encryptedRequest = encrypt(sessionKey, (unsigned char *)request, strlen(request), &cipherLength);
	print_hex((const char *)encryptedRequest, cipherLength);
	if(encryptedRequest == NULL)
	{
		fprintf(stderr, "Encryption Failed in endSession().\n");
		return;
	}
	/* Send the request to the server */
	if(send(sockfd, encryptedRequest, cipherLength, 0) == -1)
        {
		fprintf(stderr,"send(): %s\n", strerror(errno));
		return;
	}
}


/******************************************************************************************
Function: delegate()
Description: This function forms a delegation request of the form:
	@DEL:<UID>:<delegateToClient>:<GET/PUT/BOTH>:<Validity Period>: <Propagation Flag>
and sends the encrypted request to the server.
It waits for the server response to know if the request of executed successfully or not 
and return the success flag to the caller accordingly.
******************************************************************************************/

int delegate(int sockfd, char * UID, char * delegateToClient, int rightChoice, char * validityPeriod, char * propagationFlag, unsigned char * sessionKey)
{
	int bytesCount;
	char buffer[MAXDATASIZE] = {0};
	const char * right = NULL;
	/*Assign the right based on the input integer choice */
	if(rightChoice == 1)
		right = "GET";
	else if(rightChoice == 2)
		right = "PUT";
	else if(rightChoice == 3)
		right = "BOTH";
	/* Calculate the buffer size required for the request */
	int requestSize = 5 + UIDSIZE + 1 + strlen(delegateToClient) + 1 + strlen(right) + 1 + strlen(validityPeriod) + 1 + strlen(propagationFlag)+1;
	char * request = (char *)malloc(requestSize * sizeof(char));
	if(request == NULL)
	{
		printf("Error in allocating buffer for request.\n");
		return 0;
	}
	memset(request, 0, requestSize);
	/* Form the request for delegation */
	strncpy(request, "@DEL:", 5);
	strncat(request, UID, UIDSIZE);
	strncat(request, ":", 1);
	strncat(request, delegateToClient, strlen(delegateToClient));
	strncat(request, ":", 1);
	strncat(request, right, strlen(right));
	strncat(request, ":", 1);
	strncat(request, validityPeriod, strlen(validityPeriod));
	strncat(request, ":", 1);
	strncat(request, propagationFlag, strlen(propagationFlag));
	printf("The request is: %s\n", request);
	int cipherLength = 0;
	//printf("request size: %zd\n", strlen(request));
	/* Encrypt the request with the session key */	
	unsigned char * encryptedRequest = encrypt(sessionKey, (unsigned char *)request, strlen(request), &cipherLength);
	//printf("Encrypted Request.\n");
	//print_hex((const char *)encryptedRequest, cipherLength);
	//printf("\nLength %d\n", cipherLength);
	if(encryptedRequest == NULL)
	{
		fprintf(stderr, "Encryption Failed in delegate.\n");
		return 0;
	}
	/* Send the encrypted request to the server */
	if(send(sockfd, encryptedRequest, cipherLength, 0) == -1)
        {
		fprintf(stderr,"send(): %s\n", strerror(errno));
		return 0;
	}
	/* Wait for the server response */
	if((bytesCount = recv(sockfd, buffer, MAXDATASIZE-1, 0)) == -1)
	{
		fprintf(stderr, "recv(): %s\n", strerror(errno));
                return 0;
        }
	int plaintextLength = 0;
	//printf("\nReceived Length:%d\n", bytesCount);
	//printf("Cipher Received:\n");		
	//print_hex(buffer, bytesCount);
	if(bytesCount == 0)
		return 0;
	/* Decrypt the response received */
	unsigned char * decryptedResponse = decrypt((unsigned char *)buffer, bytesCount, sessionKey, &plaintextLength);
	if (decryptedResponse == NULL)
	{
		printf("Decryption failed in delegation.\n");
		return 0;
	}
	//printf("Length: %d\n", plaintextLength);
	printf("Received: %s\n", decryptedResponse);
	if(strcmp(decryptedResponse, "true") == 0)
		return 1;
	else
		return 0;
}

/******************************************************************************************
Function: main()
Description: This function is the main client driver. It gives options to the user, takes 
the appropriate inputs for a particular choice and calls the internal functions to provide
that service by communicating with the client.
******************************************************************************************/

int main(int argc, char * argv[])
{
	printf("Welcome to Secure Directory Service!!\n");
	int choice = 0;
	unsigned char * sessionKey = NULL;
	int sockfd;
	char filesRequested[10][UIDSIZE] = {0};
	int numberOfFilesRequested = 0;
	do
	{
		printf("\n\nPlease make a choice: \n"
	     		"1) Establish Session \n"
		  	"2) GET Document \n"
		  	"3) PUT Document \n"
		  	"4) DELEGATE \n"
			"5) Terminate Session \n"
		  	"6) Exit \n");
	   	char choiceString[5];
		if(fgets(choiceString, sizeof(choiceString), stdin) == NULL)
		{
			printf("Error in parsing user choice input.\n");
			continue;
		}
		if(strip_newline(choiceString, 5) != 1)
		{
		        printf("Wrong Input. Did you exceed the limit.\n");
	       		continue;
     	  	}
		choice = atoi(choiceString);
		if (choice == 6)
		{
			//close(sockfd);	
			printf("Exiting..\n");
			return 0;
		}
		/* User is not allowed to execute other services without establishing a secure session with the server */
		else if ((choice != 1) && (!sessionEstablished)) 
		{
			printf("You must establish a secure session first!!\n");
			continue;
   		}
		/* Choice 1 is to establish a secure session. It takes the server name/IP as the input
		   and calls ssession() */
		else if (choice == 1)
		{
			char hostname[20] = {0};
			printf("Hostname (Max 18 characters):\n");
			if(fgets(hostname, 20, stdin)== NULL)
			{
				printf("Wrong Input.\n");
				continue;
			}
			if(strip_newline(hostname, 20) != 1)	
			{
	        		printf("Wrong Input. Did you exceed the limit.\n");
	        		continue;
			}
			sockfd = ssession(hostname, &sessionKey);
		}
		/* Choice 2 is GET file. It takes the UID of the file as input. It is assumed that the
		   client has the UID of all the files he wants to retrieve. For this purpose, we
		   return the UID for any new file stored by this user on the server and expect the 
		   user to store this UID somewhere for future operations on this file. */
		  
  		else if (choice == 2) 
		{
			char * UID = (char *)malloc(UIDSIZE*sizeof(char)+1);
			memset(UID, 0, UIDSIZE+1);
			printf("Please enter the UID of the file:\n");
			if(fgets(UID, UIDSIZE, stdin)== NULL)
			{
				printf("Wrong Input.\n");
				continue;
			}
			if(strip_newline(UID, UIDSIZE) != 1)	
			{
		       		printf("Wrong Input. Did you exceed the limit.\n");
		       		continue;
			}
			/* Call the get function */
			int result = get(sockfd, UID, sessionKey);
			if(result == 1)
			{
				printf("File saved at the local directory successfully.\n");
				strncpy(filesRequested[numberOfFilesRequested++], UID, UIDSIZE);
			}
			else
			{
				printf("Error in fetching the file from the server.\n");
			}
		}	
		/* Choice 3 is PUT file option. The name of the file, new/old status and 
		   security property choice are taken as input. If the file is new, any name
		   can be given. If the file is already present on the server, the file is 
		   expected to be stored with name <UID>.txt. */   		
		else if (choice == 3) 
		{
			char * UID = (char *)malloc((UIDSIZE+1)*sizeof(char));
			memset(UID, 0, UIDSIZE+1);
			int newFile=0;
			int securityProperty = 0;
			char filename[50] = {0};
			printf("Okay!! So you would like to put a file on the server.\n");
			printf("Please enter the filename (Absolute Path Max size: 50):\n");
			if(fgets(filename, 50, stdin)== NULL)
			{
				printf("Wrong Input.\n");
				continue;
			}
			if(strip_newline(filename, 50) != 1)	
			{
		        	printf("Wrong Input. Did you exceed the limit.\n");
		        	continue;
			}
			long filesize = 0;
			char * fileData = readFile(filename, &filesize);
			if(fileData == NULL)
			{
				printf("Problem while reading the file.\n");
				continue;
			}
			printf("Is this a new file (Is the UID not known?). Enter 1/0 for Yes/No\n");
			if(fgets(choiceString, sizeof(choiceString), stdin) == NULL)
			{
				printf("Error in parsing user choice input.\n");
				continue;
			}
			if(strip_newline(choiceString, 5) != 1)
			{
			       	printf("Wrong Input. Did you exceed the limit.\n");
		       		continue;
	      	  	}
			newFile = atoi(choiceString);
			if(newFile == 1)
			{
				strncpy(UID, "NIL", 3);
			}			
			else if(newFile == 0)
			{
				getUID(filename, UID);
			}			
			else
			{
				printf("Wrong Input.\n");
				continue;
			}
				
			printf("Which security property would you like to have?");
			printf("\n1) None \n"
	  	      	 	"2) Confidentiality \n"
	  	 		 "3) Integrity \n");
			if(fgets(choiceString, sizeof(choiceString), stdin) == NULL)
			{
				printf("Error in parsing user choice input.\n");
				continue;
			}
			if(strip_newline(choiceString, 5) != 1)
			{
	        		printf("Wrong Input. Did you exceed the limit.\n");
       				continue;
      	  		}
			securityProperty = atoi(choiceString);
			if((securityProperty!=1) && (securityProperty!=2) && (securityProperty!=3))
			{
				printf("Wrong Input for securityProperty.\n");
				continue;
			}
			/* Call put() function */
			int result = put(sockfd, UID, fileData, filesize, securityProperty, sessionKey);
			if(result == 1)	
				printf("File has been stored on the server successfully.");
			else
				printf("Failure in storing the file on the server.\n");
		}
		/* Choice 4 is delegation. The UID of the file, the client ID, rights to be delegated
		   validity period and propagation right are taken as input from the user */
	   	else if (choice == 4) 
		{
			int rightChoice = 0;
			char rightChoiceString[5] = {0};
			char validityPeriod[20] = {0};
			char delegateToClient[30] = {0};
			char * UID = (char *)malloc(UIDSIZE*sizeof(char)+1);
			memset(UID, 0, UIDSIZE+1);
			printf("Please enter the UID of the file:\n");
			if(fgets(UID, UIDSIZE, stdin)== NULL)
			{
				printf("Wrong Input.\n");
				return 0;
			}
			if(strip_newline(UID, UIDSIZE) != 1)
			{
				printf("Wrong Input. Did you exceed the limit.\n");
				return 0;
			}
			printf("Enter the client ID(Enter ALL to allow everyone):\n");
			if(fgets(delegateToClient, 30, stdin)== NULL)
			{
				printf("Wrong Input.\n");
				return 0;
			}
			if(strip_newline(delegateToClient, 50) != 1)
			{
				printf("Wrong Input. Did you exceed the limit.\n");
				return 0;
			}
			printf("What rights do you want to delegate:\n"
				"1. GET\n"
				"2. PUT\n"
				"3. BOTH\n");
			if(fgets(rightChoiceString, sizeof(rightChoiceString), stdin) == NULL)
			{
				printf("Error in parsing user choice input.\n");
				return 0;
			}
			if(strip_newline(rightChoiceString, 5) != 1)
			{
				printf("Wrong Input. Did you exceed the limit.\n");
				return 0;
			}
			rightChoice = atoi(rightChoiceString);
			printf("Please enter the validityPeriod.\n");	
			if(fgets(validityPeriod, sizeof(validityPeriod), stdin) == NULL)
			{
				printf("Error in parsing user choice input.\n");
				return 0;
			}
			if(strip_newline(validityPeriod, 20) != 1)
			{
				printf("Wrong Input. Did you exceed the limit.\n");
				return 0;
			}
			char propagationFlag[5] = {0};
			printf("Do you want to allow propagation? (0/1):\n");
			if(fgets(propagationFlag, sizeof(propagationFlag), stdin) == NULL)
			{
				printf("Error in parsing user choice input.\n");
				return 0;
			}
			if(strip_newline(propagationFlag, 5) != 1)
			{
				printf("Wrong Input. Did you exceed the limit.\n");
				return 0;
			}
			int result = delegate(sockfd, UID, delegateToClient, rightChoice, validityPeriod, propagationFlag, sessionKey);
			if(result == 1)
				printf("Delegation Successful.\n");
			else
				printf("Delegation Failed.\n");
		}
		/*Choice 5 is termination request. The used is asked to confirm termination. 
		  If confirmed, call endSession to put all the requested files to the server 
		  and inform the server about session termination. Finally, delete the session
		  key and close the socket. */
		
		else if (choice == 5) 
		{
			int terminationRequest = 0;
			printf("Are you sure you want to terminate the session?\n");
			if(fgets(choiceString, sizeof(choiceString), stdin) == NULL)
			{
				printf("Error in parsing user choice input.\n");
				continue;
			}
			if(strip_newline(choiceString, 5) != 1)
			{
			       	printf("Wrong Input. Did you exceed the limit.\n");
		       		continue;
	      	  	}
			terminationRequest = atoi(choiceString);
			if(terminationRequest == 0)
				continue;
			else
			{
				endSession(sockfd, filesRequested, numberOfFilesRequested, sessionKey);
				free(sessionKey);
				close(sockfd);
				return 0;		
			}
		}
   		else 
		{
        		printf("Invalid Choice");
        	}
	} while (choice != 6);
	return 0;
}		
/*******************************************EOF**************************************************/
