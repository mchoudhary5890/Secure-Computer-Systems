/*************************************SERVER.C********************************************
Module: server.c
Description: This is the main server module that listens on the service port waiting for 
connection requests, establishes a secure session with the clients and serve them based
on the requests received. 
******************************************************************************************/
#include "headers.h"
#include "handshakeHelper.h"
#include "networkHelper.h"
#include "genericHelper.h"
#define BACKLOG 5

const char * serverPrivateKeyFile = "server-key.pem";
const char * serverCertFile = "server-cert.pem";
const char * servicePort = "5891";


/******************************************************************************************
Function: processGetRequest()
Description: extracts the parameters from a formated get request and calls sddr_get_file()
function to verify the access and fetch the file if access allowed.
******************************************************************************************/
char * processGetRequest(unsigned char * request, unsigned char * clientPublicKey, int cpkLength, char * clientName)
{
	char * requestType = strtok((char *)request, ":");
	char * UID = strtok(NULL, ":");
	char * buff = NULL;
	printf("request Type: %s\n", requestType);
	printf("UID: %s\n", UID);
	char * ret_true = "true";
	char * ret_false = "false";
	buff = sddr_get_file(UID, clientPublicKey, cpkLength, clientName);
	if(buff == NULL)
		return ret_false;
	else	
		return buff;
} 


/******************************************************************************************
Function: processPutRequest()
Description: extracts the parameters from a formated PUT request and calls sddr_put_file()
function to verify the access and put the file if action allowed.
******************************************************************************************/
char * processPutRequest(unsigned char * request, unsigned char * clientPublicKey, int cpkLength, char * clientName)
{
	char * requestType = strtok((char *)request, ":");
	char * securityFlag = strtok(NULL, ":");
	char * UID = strtok(NULL, ":");
	char * fileData = strtok(NULL, ":");
	char * result = NULL;
	printf("Request Type:%s\n", requestType);
	printf("Security Flag:%s\n", securityFlag);
	printf("UID:%s\n", UID);
	printf("fileData:%s\n", fileData);
	//printf("\nClient's Public Key:\n");
	//print_hex((const char *)clientPublicKey, cpkLength);
	result = sddr_put_file(UID,clientPublicKey,securityFlag, fileData, cpkLength, clientName);
	return result;
}


/******************************************************************************************
Function: processDelegateRequest()
Description: extracts the parameters from a formated delegate request and calls the 
sddr_delegate_file() function to verify delegation authorization and update the access
contol list to add the new delegation for the corresponding file.
******************************************************************************************/
char * processDelegateRequest(unsigned char * request, unsigned char * clientPublicKey, int cpkLength, char * clientName)
{
	char * retTrue = "true";
	char * retFalse = "false";
	char * requestType = strtok((char *)request, ":");
	char * UID = strtok(NULL, ":");
	char * delegateToClient = strtok(NULL, ":");
	char * right = strtok(NULL, ":");
	char * validityPeriod = strtok(NULL, ":");
	char * propagationFlag = strtok(NULL, ":");
	printf("Delegation Processing\n%s %s %s %s %s %s\n", requestType, UID, delegateToClient, right, validityPeriod, propagationFlag);
	if(sddr_delegate_file(UID, clientPublicKey, delegateToClient, clientName, atol(validityPeriod), right, propagationFlag,cpkLength) == 1)
		return retTrue;
	else
		return retFalse;
}	


/******************************************************************************************
Function: processRequest()
Description: A wrapper to provide a general request processor which calls the appropriate
request processor based on the type of the request.
******************************************************************************************/
char * processRequest(unsigned char * request, unsigned char * clientPublicKey, int cpkLength, int * terminate, char * clientName)
{
	if(strstr((char *)request, "@GET:") != NULL)
		return processGetRequest(request, clientPublicKey, cpkLength, clientName);
	else if(strstr((char *)request, "@PUT:") != NULL)
		return processPutRequest(request, clientPublicKey, cpkLength, clientName);
	else if(strstr((char *)request, "@DEL:") != NULL)
		return processDelegateRequest(request, clientPublicKey, cpkLength, clientName);
	else if(strstr((char *)request, "@TER:") != NULL)
		*terminate = 1;
	return NULL;
}


/******************************************************************************************
Function: clientHandler()
Description: Runs in the child process for each of the clients with session waiting for
the requests. If encrypted request received, it decrypts the request and calls the 
processRequest() function to process the request and returns the reponse to the client.
The loop ends only when the client asks the the server to terminate the request.
******************************************************************************************/
void clientHandler(int newsockfd, unsigned char * sessionKey, unsigned char * clientPublicKey, int cpkLength, char * clientName)
{
	int bytesCount = 0;
	int terminate = 0;
	char buffer[MAXDATASIZE];
	while(1)
	{
		printf("Waiting for Request.\n");
		/* Wait for the request */
		if((bytesCount = recv(newsockfd, buffer, MAXDATASIZE-1, 0)) == -1)
		{
			fprintf(stderr, "recv(): %s\n", strerror(errno));
                	return;
        	}
		int plaintextLength = 0;
		/* Decrypt the request received */
		unsigned char * decryptedRequest = decrypt((unsigned char *)buffer, bytesCount, sessionKey, &plaintextLength);
		if (decryptedRequest == NULL)
		{
			printf("Decryption failed in clientHandler.\n");
			return;
		}
		printf("Received: %s\n", decryptedRequest);
		/* Process the request received */
		char * processResult = processRequest(decryptedRequest, clientPublicKey, cpkLength, &terminate, clientName);
		if(terminate == 1)
		{
			printf("Terminating Session.\n");
			free(sessionKey);
			free(clientPublicKey);
			return;
		}
		printf("The response is: %s\n", processResult);
		int cipherLength = 0;
		/* Encrypt the response */
		unsigned char * encryptedResponse = encrypt(sessionKey, (unsigned char *)processResult, strlen(processResult), &cipherLength);
		if(encryptedResponse == NULL)
		{
			fprintf(stderr, "Encryption Failed in put.\n");
			return;
		}
		/* Send the response to the client */
		if(send(newsockfd, encryptedResponse, cipherLength, 0) == -1)
        	{
			fprintf(stderr,"send(): %s\n", strerror(errno));
			return;
		}
	}		
}


/******************************************************************************************
Function: main()
Description: main() function which makes the server up by binding it to a port, listening
and accepting the connections. It performs diffie hellman key exchange protocol to
establish a secure and trusted communication channel with each client and finally, calls
clientHandler() to received and process the further requests in this session. 
******************************************************************************************/
int main(int argc, char * argv[])
{
	int bytesCount = 0;
	char buffer[MAXDATASIZE];
	int sockfd, newsockfd;
	struct addrinfo hints, * res, *currentRes;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	int fcallResult;
	int yes = 1;
	socklen_t clientAddrLen;
	struct sockaddr_storage clientAddr;
	char des[INET6_ADDRSTRLEN];
	if((fcallResult = getaddrinfo(NULL, servicePort,  &hints, &res))!=0)
	{
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(fcallResult));
		return 1;
	}
	currentRes = res;
	while(currentRes != NULL)
	{
		currentRes = currentRes->ai_next;
		if((sockfd = socket(currentRes->ai_family, currentRes->ai_socktype, currentRes->ai_protocol)) == -1)
		{
			fprintf(stderr, "socket(): %s\n", strerror(errno));
			continue;
		}
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
		{
			fprintf(stderr, "setsockopt(): %s\n", strerror(errno));
			exit(1);
		}
		if(bind(sockfd, currentRes->ai_addr, currentRes->ai_addrlen) == -1)
		{
			close(sockfd);
			fprintf(stderr, "bind(): %s\n", strerror(errno));
			continue;
		}
		break;
	}
	if(currentRes == NULL)
	{
		fprintf(stderr, "Failed to bind.\n");
		return 2;
	}
	freeaddrinfo(res);
	if(listen(sockfd, BACKLOG) == -1)
	{
		fprintf(stderr, "listen(): %s\n", strerror(errno));
		exit(1);
	}
	int lengthOfServerCert = 0;
	char * serverCertPEM = readCertInPEM(serverCertFile, &lengthOfServerCert);
	printf("Listening on port : %s\n", servicePort);
	while(1)
	{
		clientAddrLen = sizeof(clientAddr);
		if((newsockfd = accept(sockfd, (struct sockaddr *)&clientAddr, &clientAddrLen)) == -1)
		{
			fprintf(stderr, "accept(): %s\n", strerror(errno));
			continue;
		}
		inet_ntop(clientAddr.ss_family, getInAddr((struct sockaddr *)&clientAddr), des, sizeof(des));
		printf("Server: Received Connection from client %s\n", des);
		if(fork() == 0)
		{
			close(sockfd);
			/* Send the server certificate to the client */
			if(send(newsockfd, serverCertPEM, lengthOfServerCert, 0) == -1)
			{
				fprintf(stderr,"send(): %s\n", strerror(errno));
				exit(1);
			}
			/* Receive the client certificate */
			if((bytesCount = recv(newsockfd, buffer, MAXDATASIZE-1, 0)) == -1)
		        {
               			fprintf(stderr, "recv(): %s\n", strerror(errno));
               			exit(1);
        		}
			X509 * clientCertInX509 = PEMToX509(buffer);
			X509 * CACertInX509 = readCACertInX509();
			/* Verify the client certificate */
			if(!verifyCert(CACertInX509, clientCertInX509))
        		{
                		fprintf(stderr, "Client Certificate Verification Failed.\n");
                		close(newsockfd);
                		exit(1);
        		}
        		printf("Client Certificate Verification Successful.\n");
			int clientPublicKeyLength = 0;
			/* Extract the common name and public key from the client certificate */
			unsigned char * clientPublicKey = extractPublicKeyFromCert(clientCertInX509, &clientPublicKeyLength);
			char * clientName = getSubjectFromCert(clientCertInX509);
			//printf("Client's Public Key: \n");
			//print_hex((const char *)clientPublicKey, clientPublicKeyLength);
			//printf("Client Name: %s\n", clientName);
			int lengthOfEncryptedRandomKey = 0;
			unsigned char * randomKey = NULL;
			/* Encrypt and send a random key */
			unsigned char * encryptedRandomKey = encryptRandomKey(clientCertInX509, &lengthOfEncryptedRandomKey, &randomKey);
			if(send(newsockfd, encryptedRandomKey, lengthOfEncryptedRandomKey, 0) == -1)
                        {
                                fprintf(stderr,"send(): %s\n", strerror(errno));
                                exit(1);
                        }
			/* Receive a random key from the client */
			if((bytesCount = recv(newsockfd, buffer, MAXDATASIZE-1, 0)) == -1)
        		{		
 		                fprintf(stderr, "recv(): %s\n", strerror(errno));
                		exit(1);
        		}
        		int lengthOfDecryptedRandomKey;
			/* Decrypt the random key received */
        		unsigned char * decryptedRandomKey = decryptRandomKey(serverPrivateKeyFile, (unsigned char *)buffer, (size_t)bytesCount, &lengthOfDecryptedRandomKey);
        		if(!decryptedRandomKey)
        		{
                		fprintf(stderr, "Error While decrypting random key received. \n");
                		close(sockfd);
                		return 1;
        		}
			//printf("Sent Random Key:\n");
			//print_hex((const char *)randomKey, KEY_SIZE_IN_BYTES);
			//printf("Received Random Key:\n");
			//print_hex((const char *)decryptedRandomKey, lengthOfDecryptedRandomKey);
			/* Generate the session key from the two random keys */	
			unsigned char * sessionKey = generateSessionKey(randomKey, decryptedRandomKey);	
			//printf("\nSession Key: \n");
			//print_hex((const char *)sessionKey, KEY_SIZE_IN_BYTES);
			/* Call clientHandler() to serve this authenticated client */
			clientHandler(newsockfd, sessionKey, clientPublicKey, clientPublicKeyLength, clientName);	
			close(newsockfd);
			exit(0);
		}
		close(newsockfd);
	}
	printf("Terminating Server!!\n");	
	return 0;
}
/*********************************************EOF*****************************************/
