#ifndef GENERICHELPER_H
#define GENERICHELPER_H

void print_hex(const char *, int);
int strip_newline(char *, int);
char * readFile(char *, long *);
char * getSubjectFromCert(X509 *);
char * getNameWithoutExntension(char *);
void getUID(char *, char *);
EVP_PKEY * getPublicKey(const char *);
EVP_PKEY * getPrivateKey(const char *);

#endif
