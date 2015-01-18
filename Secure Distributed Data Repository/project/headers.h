#ifndef HEADERS_H
#define HEADERS_H
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>
#include<netdb.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include<openssl/evp.h>
#include<openssl/rsa.h>
#include<openssl/rand.h>
#include <libgen.h>
#define KEY_SIZE_IN_BYTES 16
#define MAXDATASIZE 2000
#define UIDSIZE 80
#define PUBLICKEYSIZE 256


char * sddr_get_file(char *, unsigned char *, int, char *);
char * sddr_put_file(char *, unsigned char *, char *, char *,int , char *);
int sddr_delegate_file(char *, unsigned char *, char *, char *, long, char *, char *, int);

#endif


