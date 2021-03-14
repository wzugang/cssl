#include "cssl.h"
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

//#include <stdio.h>
//main()
//{
//    FILE * fp;
//    char buffer[80];
//    fp = popen("cat /etc/passwd", "r");
//    fgets(buffer, sizeof(buffer), fp);
//    printf("%s", buffer);
//    pclose(fp);
//}
#define CHK_ERR(err, s, ret) if((err) == -1) { perror(s); return ret; }
#define CHK_RV(rv, s, ret) if((rv) != 1) { printf("%s error\n", s); return ret; }

#define CHK_NULL(x, s, ret) do { if((x) == NULL) { printf("%s error\n", s); return ret; } } while(0)
#define CHK_SSL(err, s, ret) fo { if((err) == -1) { ERR_print_errors_fp(stderr); return ret; } } while(0)

typedef void* (*cssl_alloc_fun)(size_t size);
typedef void  (*cssl_free_fun) (void* ptr);

cssl_alloc_fun cssl_alloc =  malloc;
cssl_free_fun  cssl_free =  free;

//typedef enum CSSL_VERSION
//{
//    CSSL_VERSION_1=0
//}CSSL_VERSION;


void cssl_cert_print(cssl* ssl);

int cssl_init()
{
    (void)SSL_library_init();
    (void)OpenSSL_add_all_algorithms();
    (void)SSL_load_error_strings();
    (void)RAND_poll();
    
    return 0;
}

cssl* cssl_client_open()
{
    cssl* ssl = cssl_alloc(sizeof(cssl));
    if(NULL ==ssl)
    {
        printf("cssl_open cssl_alloc error\n");
        return NULL;
    }
    
    ssl->ctx = SSL_CTX_new(TLSv1_2_client_method());
    if(NULL == ssl->ctx)
    {
        cssl_free(ssl);
        printf("cssl_open create ctx error\n");
        return NULL;
    }
    
    ssl->ssl = NULL;
    
    return ssl;
}


cssl* cssl_server_open()
{
    cssl* ssl = cssl_alloc(sizeof(cssl));
    if(NULL ==ssl)
    {
        printf("cssl_open cssl_alloc error\n");
        return NULL;
    }
    
    ssl->ctx = SSL_CTX_new(TLSv1_2_server_method());
    if(NULL == ssl->ctx)
    {
        cssl_free(ssl);
        printf("cssl_open create ctx error\n");
        return NULL;
    }
    
    ssl->ssl = SSL_new(ssl->ctx);
    if(NULL == ssl->ssl)
    {
        SSL_CTX_free(ssl->ctx);
        ssl->ctx = NULL;
        cssl_free(ssl);
        printf("cssl_open create ssl error\n");
        return NULL;
    }
    
    return ssl;
}

//如何并发,一个ctx是否可以设置多个fd
int cssl_set_fd(cssl* ssl, int fd)
{
    ssl->ssl = SSL_new(ssl->ctx);
    if(NULL == ssl->ssl)
    {
        return -1;
    }
    SSL_set_fd(ssl->ssl, fd);
    
    return 0;
}

void cssl_close(cssl* ssl)
{
    if(NULL == ssl)
    {
        return;
    }
    if(NULL != ssl->ssl)
    {
        SSL_shutdown(ssl->ssl);
        SSL_free(ssl->ssl);
        ssl->ssl = NULL;
    }
    if(NULL != ssl->ctx)
    {
        SSL_CTX_free(ssl->ctx);
        ssl->ctx = NULL;
    }
    
    cssl_free(ssl);
    ssl = NULL;
}

int cssl_read(cssl* ssl, void* buffer, int size)
{
    int len;
    len = SSL_read(ssl->ssl, buffer, size);
    if(len > 0)
    {
        return len;
    }
    else if(0 == len)
    {
        printf("cssl_read complete\n");
        return 0;
    }
    else
    {
        printf("cssl_read error : %d, %s\n", errno, strerror(errno));
        return -1;
    }
}

int cssl_write(cssl* ssl, void* buffer, int size)
{
    int ret, err;
    do
    {
        ret = SSL_write(ssl->ssl, buffer, size);
        if(ret > 0 || EAGAIN == errno)
        {
            break;
        }
        err = SSL_get_error(ssl->ssl, ret);
    }while(SSL_ERROR_WANT_WRITE == err || SSL_ERROR_WANT_READ == err);
    
    return ret;
}

void cssl_getcwd(char* pwd, int size)
{
    getcwd(pwd, size);
}

int cssl_connect(cssl* ssl)
{
    if (SSL_connect(ssl->ssl) < 0)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl->ssl));
        cssl_cert_print(ssl);
    }
    
    return 0;
}

int cssl_accept(cssl* ssl)
{
    if (SSL_accept(ssl->ssl) < 0)
    {
      return -1;
    }
    return 0;
}

void cssl_set_cipher(cssl* ssl, char* cipherlist)
{
    //set cipher ,when handshake client will send the cipher list to server  
    (void)SSL_CTX_set_cipher_list(ssl->ctx, cipherlist); //"HIGH:MEDIA:LOW:!DH"
}

int cssl_passwd_cb(char* buf, int size, int rwflag, void* userdata)
{
    strncpy(buf, userdata, strlen((char*)userdata));
}

void cssl_set_key_password(cssl* ssl, char* passwd)
{
    //passwd is supplied to protect the private key,when you want to read key
    (void)SSL_CTX_set_default_passwd_cb_userdata(ssl->ctx, passwd);
    (void)SSL_CTX_set_default_passwd_cb(ssl->ctx, cssl_passwd_cb);
}


//在SSL握手时，验证服务端证书时会被调用，res返回值为1则表示验证成功，否则为失败
static int cssl_verify_cb(int res, X509_STORE_CTX *xs)
{
    printf("SSL VERIFY RESULT :%d\n",res);
    switch (xs->error)
    {
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            printf(" NOT GET CRL!\n");
            return 1;
        default :
            break;
    }
    return res;
}

void cssl_set_ca(cssl* ssl, char* cafile)
{
    //set verify ,when recive the server certificate and verify it
    //and verify_cb function will deal the result of verification
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, cssl_verify_cb);
      
    //sets the maximum depth for the certificate chain verification that shall
    //be allowed for ctx
    SSL_CTX_set_verify_depth(ssl->ctx, 10);
    //load the certificate for verify server certificate, CA file usually load
    SSL_CTX_load_verify_locations(ssl->ctx, cafile, NULL);
}

int cssl_set_key(cssl* ssl, char* keyfile, char* passwd)
{
    cssl_set_key_password(ssl, passwd);
    //load user private key
    if(SSL_CTX_use_PrivateKey_file(ssl->ctx, keyfile, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stdout);
        printf("cssl_set_cert_key load privatekey file error!\n");
        return -1;
    }  
    if(!SSL_CTX_check_private_key(ssl->ctx)){
        ERR_print_errors_fp(stdout);
        printf("cssl_set_cert_key check private key failed\n");
        return -1;
    }
    return 0;
}

int cssl_set_cert(cssl* ssl, char* certfile)
{
    //load user certificate,this cert will be send to server for server verify
    if(SSL_CTX_use_certificate_file(ssl->ctx, certfile, SSL_FILETYPE_PEM) <= 0){ //SSL_FILETYPE_ASN1
        ERR_print_errors_fp(stdout);
        printf("cssl_set_cert_key load certificate file error!\n");
        return -1;
    }
    return 0;
}

void cssl_cert_print(cssl* ssl)
{
    X509 *cert;
    char *line;
    if(NULL ==ssl || ssl->ssl)
    {
        return;
    }
    cert = SSL_get_peer_certificate(ssl->ssl);
    if (cert != NULL) {
        printf("Digital certificate information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);  
        cssl_free(line);  
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        cssl_free(line);
        X509_free(cert);
    }  
    else
    {
        printf("No certificate information！\n");
    }
}

void print_client_cert(char* path, char* passwd)
{  
    X509 *cert =NULL;
    FILE *fp = NULL;
    fp = fopen(path,"rb");
    //从证书文件中读取证书到x509结构中，passwd为1111,此为生成证书时设置的
    cert = PEM_read_X509(fp, NULL, NULL, passwd);
    X509_NAME *name=NULL;
    char buf[8192]={0};
    BIO *bio_cert = NULL;
    //证书持有者信息
    name = X509_get_subject_name(cert);
    X509_NAME_oneline(name,buf,8191);
    printf("ClientSubjectName:%s\n",buf);
    memset(buf,0,sizeof(buf));
    bio_cert = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio_cert, cert);
    //证书内容
    BIO_read( bio_cert, buf, 8191);
    printf("CLIENT CERT:\n%s\n",buf);
    if(bio_cert)BIO_free(bio_cert);
    fclose(fp);
    if(cert) X509_free(cert);
}

//打印服务端证书相关内容  
void print_peer_cert(cssl* ssl)
{  
    X509* cert= NULL;
    X509_NAME *name=NULL;
    char buf[8192]={0};
    BIO *bio_cert = NULL;
    //获取server端证书
    cert = SSL_get_peer_certificate(ssl->ssl);
    //获取证书拥有者信息
    name = X509_get_subject_name(cert);
    X509_NAME_oneline(name,buf,8191);
    printf("ServerSubjectName:%s\n",buf);
    memset(buf,0,sizeof(buf));
    bio_cert = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio_cert, cert);
    BIO_read( bio_cert, buf, 8191);
    //server证书内容
    printf("SERVER CERT:\n%s\n",buf);
    if(bio_cert)BIO_free(bio_cert);
    if(cert)X509_free(cert);
}

// 1． 首先介绍如何生成客户和服务端证书(PEM)及密钥。
// 在linux环境下下载并安装openssl开发包后，通过openssl命令来建立一个SSL测试环境。
// 1） 建立自己的CA
//  在openssl安装目录的misc目录下，运行脚本：./CA.sh -newca，出现提示符时，直接回车。  运行完毕后会生成一个demonCA的目录，里面包含了ca证书及其私钥。
// 2） 生成客户端和服务端证书申请：
//  openssl  req  -newkey  rsa:1024  -out  req1.pem  -keyout  sslclientkey.pem
// openssl  req  -newkey  rsa:1024  -out  req2.pem  -keyout  sslserverkey.pem
// 3) 签发客户端和服务端证书
// openssl  ca  -in  req1.pem  -out  sslclientcert.pem
// openssl  ca  -in  req2.pem  -out  sslservercert.pem
// 4) 运行ssl服务端：
// openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3 
// 当然我们也可以使用openssl自带的客户端：
// openssl s_client -ssl3 -CAfile demoCA/cacert.pem





















