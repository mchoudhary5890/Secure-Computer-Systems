#ifndef HANDSHAKEHELPER_H
#define HANDSHAKEHELPER_H

X509 * readCACertInX509();
X509 * PEMToX509(char *pem);
int verifyCert(X509 *, X509 *);
unsigned char * extractPublicKeyFromCert(X509 *, int *);
char * readCertInPEM(const char *, int *);
unsigned char * encryptRandomKey(X509 *, int *, unsigned char ** );
unsigned char * decryptRandomKey(const char *, unsigned char *, size_t, int *);
unsigned char * generateSessionKey(unsigned char *, unsigned char *);

#endif
