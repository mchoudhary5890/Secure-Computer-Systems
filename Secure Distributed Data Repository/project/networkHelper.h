#ifndef NETWORKHELPER_H
#define NETWORKHELPER_H

void * getInAddr(struct sockaddr *);
unsigned char* prepend(unsigned char *, unsigned char *, size_t, size_t);
unsigned char * encrypt(unsigned char *, unsigned char *, int, int *);
unsigned char * decrypt(unsigned char * , int , unsigned char * , int * );

#endif
