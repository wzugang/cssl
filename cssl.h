#ifndef __CSSL_H
#define __CSSL_H

#include <openssl/ssl.h>

typedef struct cssl
{
    SSL_CTX *ctx;
    SSL *ssl;
    
}cssl;

int cssl_init();
cssl* cssl_client_open();
cssl* cssl_server_open();
int cssl_set_fd(cssl* ssl, int fd);
void cssl_close(cssl* ssl);
int cssl_read(cssl* ssl, void* buffer, int size);
int cssl_write(cssl* ssl, void* buffer, int size);
void cssl_getcwd(char* pwd, int size);
int cssl_connect(cssl* ssl);
int cssl_accept(cssl* ssl);
void cssl_set_cipher(cssl* ssl, char* cipherlist); //多个算法list
void cssl_set_ca(cssl* ssl, char* cafile);
int cssl_set_key(cssl* ssl, char* keyfile, char* passwd);
int cssl_set_cert(cssl* ssl, char* certfile);
void print_client_cert(char* path, char* passwd);
void print_peer_cert(cssl* ssl);


#endif

