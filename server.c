#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include "cssl.h"

// gcc server.c cssl.c -o server -lssl -lcrypto
// openssl req -newkey rsa:2048 -nodes -keyout rsa_keyServer.pem -x509 -days 365 -out certServer.cer -subj "/C=CN/ST=GD/L=GZ/O=abc/OU=defg/CN=hijk/emailAddress=132456.com"
//1) 建立自己的CA  在openssl安装目录的misc目录下，运行脚本：./CA.sh -newca，出现提示符时，直接回车。  运行完毕后会生成一个demonCA的目录，里面包含了ca证书及其私钥。
//2) 生成客户端和服务端证书申请：  openssl  req  -newkey  rsa:1024  -out  req1.pem  -keyout  sslclientkey.pemopenssl  req  -newkey  rsa:1024  -out  req2.pem  -keyout  sslserverkey.pem
//3) 签发客户端和服务端证书 openssl  ca  -in  req1.pem  -out  sslclientcert.pem / openssl  ca  -in  req2.pem  -out  sslservercert.pem
//4) 运行ssl服务端： openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3  当然我们也可以使用openssl自带的客户端： openssl s_client -ssl3 -CAfile demoCA/cacert.pem
//https://www.cnblogs.com/littleatp/p/5878763.html
//openssl编译 ./Configure linux-x86_64 --prefix=$(pwd)/build no-asm shared

//openssl genrsa -out ca.key -des 2048 #需要输入密码
//openssl rsa -in ca.key -text -noout
//openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/C=CN/ST=Zhejiang/L=Hangzhou/O=Company/OU=Department/CN=domain"
//openssl x509 -in ca.crt -text -noout

//openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf

//openssl genrsa -out client.key -des3 1024
//openssl genrsa -out client.key 1024
//openssl req -new -key client.key -out client.csr -subj "/C=CN/ST=Zhejiang/L=Hangzhou/O=Company/OU=Department/CN=127.0.0.1"
//openssl ca -in client.csr -cert ca.crt -keyfile ca.key -policy policy_anything -out client.crt -config ./openssl-OpenSSL_1_0_2u/build/ssl/openssl.cnf #需要事先创建目录,执行命令输入yy确认即可

//openssl genrsa -out server.key -des3 1024 -keyform PEM
//openssl genrsa -out server.key 1024
//openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=Zhejiang/L=Hangzhou/O=Company/OU=Department/CN=aaa"  -outform PEM
//openssl ca -in server.csr -cert ca.crt -keyfile ca.key -policy policy_anything -out server.crt -config ./openssl-OpenSSL_1_0_2u/build/ssl/openssl.cnf

//证书测试,经过测试证书是OK的
//openssl s_server -cert server.crt -key server.key -CAfile ca.crt -ssl3
//openssl s_client -cert client.crt -key client.key -ssl3 -CAfile ca.crt

//openssl rsa -in server.key -out server.key #去除key密码

//私钥有密码，公钥与证书没有密码

//以下在签名证书时需要使用
//mkdir -p ./demoCA/newcerts
//touch ./demoCA/index.txt
//echo 01 > ./demoCA/serial

// echo 01 > /etc/pki/CA/serial
// touch /etc/pki/CA/index.txt


//私钥加密
//openssl rsa -in private.pem -aes256 -passout pass:1234 -out enc_private.pem
//私钥去取加密
//openssl rsa -in enc_private.pem -passin pass:1234 -out private.pem
//生成公钥
//openssl rsa -in private.pem -pubout -out public.pem
//生成自签名证书
//openssl req -new -key private.pem -out cert.crt -subj "/C=CN/ST=hubei/L=SZ/O=test/OU=test/CN=http://test.com"

//openssl req -newkey rsa:1024 -keyout testkey.pem -keyform PEM -out testreq.pem -outform PEM
//openssl ca -in testreq.pem

//[root@aliyun cssl]# ./server 50000
//140317043230640:error:0906D06C:PEM routines:PEM_read_bio:no start line:pem_lib.c:707:Expecting: CERTIFICATE
//140317043230640:error:140AD009:SSL routines:SSL_CTX_use_certificate_file:PEM lib:ssl_rsa.c:484:
//cssl_set_cert_key load certificate file error!
//证书不要有密码

//get,set,cd为自定义命令
////请求命令类型, 0x0000-0x7fff, shell命令0, 自定义命令1,2,3,4....
////响应命令类型, 0x8000-0xffff, shell命令0, 自定义命令1,2,3,4....
typedef struct mycmd
{
    unsigned short type; // 命令类型
    unsigned short typelen; // 命令参数长度
    size_t extlen; // 扩展数据长度, 可以为0
    void* data[0]; //数据(命令参数+数据)
}mycmd;
//请求响应使用同一结构,发送时可以先把前面数据发了,extdata后续再发
//有些请求需要回复, 有些不用

size_t sys_filesize(const char *filename);
char* sys_filepath(char* filepath);
char* sys_popen(char* cmd);
int sys_getfile(char* filename, char* buffer, size_t size, size_t* len);

//get filename
//put filename

//shell0,get1, put2,cd3
int sys_execute(cssl* ssl)
{
    char* ptr;
    size_t len;
    unsigned short type = 0;
    unsigned short typelen = 0;
    size_t extlen = 0;
    size_t filelen = 0;
    int ret = 0;
    int pos = 0;
    int headsize = sizeof(mycmd);
    mycmd cmd;
    unsigned char* pcmd = (unsigned char*)&cmd;
    char* filepathname;
    char filepath[1024];
    char recvbuffer[4096];
    int bufflen = sizeof(recvbuffer);
    (void)memset(recvbuffer, 0, bufflen);
    
    do
    {
        ret = cssl_read(ssl, &recvbuffer[pos], headsize-pos);
        if(ret < 1)
        {
            return -1;
        }
        pos += ret;
    }while(pos < headsize);
    (void)memcpy(&cmd, recvbuffer, headsize);
    type = cmd.type;
    typelen = cmd.typelen; //已包含字符串结束符
    if(typelen > 1024) //命令不能大于1024字节
    {
        return -1;
    }
    
    pos = 0;
    do
    {
        ret = cssl_read(ssl, &recvbuffer[pos], typelen-pos);
        if(ret < 1)
        {
            return -1;
        }
        pos += ret;
    }while(pos < typelen);
    recvbuffer[pos-1] = '\0';
    
    cmd.type = 0x8000 + type; //类型转换
    cmd.typelen = 0; //接收数据使用extlen
    if(0 == type) //shell
    {
        ptr = (char*)sys_popen(recvbuffer);
        len = strlen(ptr)+1;
        cmd.extlen = len;
        
        pos = 0;
        do
        {
            ret = cssl_write(ssl, &pcmd[pos], headsize-pos);
            if(ret < 0)
            {
                free(ptr);
                return -1;
            }
            pos += ret;
        }while(pos < headsize);
        
        pos = 0;
        do
        {
            ret = cssl_write(ssl, &ptr[pos], len-pos);
            if(ret < 0)
            {
                free(ptr);
                return -1;
            }
            pos += ret;
        }while(pos < len);
        
        free(ptr);
        return 0;
    }
    else if(1 == type) //get
    {
        //保存文件名
        (void)memcpy(filepath, recvbuffer, typelen);
        //获取文件完整路径
        filepathname = sys_filepath(filepath);
        //获取文件大小
        extlen = sys_filesize(filepathname);
        cmd.extlen = extlen;
        
        //发送响应头
        pos = 0;
        do
        {
            ret = cssl_write(ssl, &pcmd[pos], headsize-pos);
            if(ret < 0)
            {
                printf("get write head error : %s\n", filepathname);
                return -1;
            }
            pos += ret;
        }while(pos < headsize);
        
        if(extlen > 0)
        {
            //发送文件
            filelen = 0;
            do
            {
                ret = sys_getfile(filepathname, recvbuffer, bufflen, &len);
                if(ret < 0)
                {
                    return -1;
                }
                filelen += len;
                pos = 0;
                do
                {
                    ret = cssl_write(ssl, &recvbuffer[pos], len-pos);
                    if(ret < 0)
                    {
                        printf("get write file error : %s\n", filepathname);
                        return -1;
                    }
                    pos += ret;
                }while(pos < len);
            }while(filelen < extlen);
        }
    }
    else if(2 == type) //put, 读取文件并保存,不用回
    {
        //保存文件名
        (void)memcpy(filepath, recvbuffer, typelen);
        //获取文件完整路径
        filepathname = sys_filepath(filepath);
        //获取文件大小
        extlen = cmd.extlen;
        
        //读取文件内容并保存文件
        do
        {
            ret = cssl_read(ssl, recvbuffer, bufflen);
            if(ret < 1) //0代表断开
            {
                printf("put read file error : %s\n", filepathname);
                (void)sys_putfile(NULL, NULL, 0);
                return -1;
            }
            filelen += ret;
            
            //写文件
            ret = sys_putfile(filepathname, recvbuffer, ret);
            if(ret < 0)
            {
                printf("put write file error : %s\n", filepathname);
                (void)sys_putfile(NULL, NULL, 0);
                return -1;
            }
        }while(filelen < extlen);
        
        (void)sys_putfile(NULL, NULL, 0);
    }
    else if(3 == type) //cd,不用回
    {
        //保存路径
        (void)memcpy(filepath, recvbuffer, typelen);
        //获取完整路径
        filepathname = sys_filepath(filepath);
        sys_chdir(filepathname);
    }
    else
    {
        return 0;
    }
    
    return 0;
}

size_t sys_filesize(const char *filename)
{
    struct stat buf;
    if(stat(filename, &buf)<0)
    {
        return 0;
    }
    
    return buf.st_size;
}

int sys_filelength(char* filename)
{
    int ret;
    FILE* fp = NULL;
    int size = 0;
    fp = fopen(filename, "rb");
    if(NULL == fp)
    {
        return size;
    }
    ret = fseek(fp,0,SEEK_END);
    if(0 != ret)
    {
        return size;
    }
    if ((size = ftell(fp))<0)
    {
        size = 0;
    }
    fclose(fp);
    
    return 0;
}

char* sys_popen(char* cmd)
{
    char tmp[2048];
    char* ptr;
    char* ptmp;
    FILE * fp;
    int size = 2048;
    int len = 0;
    int pos = 0;
    int tmplen = 0;
    ptr = (char*)malloc(size);
    if(NULL ==ptr)
    {
        return NULL;
    }
    (void)memset(ptr, 0, size);
    fp = popen(cmd, "r");
    (void)memset(tmp, 0, sizeof(tmp));
    while (NULL != fgets(tmp, sizeof(tmp), fp))
    {
        tmplen = strlen(tmp);
        len += tmplen;
        if(len < size)
        {
            (void)memcpy(&ptr[pos], tmp, tmplen);
            pos += tmplen;
        }
        else
        {
            while(size <= len)
            {
                size = size * 2;
            }
            
            ptmp = (char*)malloc(size);
            if(NULL == ptmp)
            {
                return NULL;
            }
            (void)memset(ptmp, 0, size);
            (void)memcpy(ptmp, ptr, len);
            free(ptr);
            ptr = ptmp;
        }
        (void)memset(tmp, 0, sizeof(tmp));
    }
    
    pclose(fp);
    
    return ptr;
}

void sys_getcwd(char* buffer, int size)
{
    (void)getcwd(buffer, size);
}

char* sys_filepath(char* filepath)
{
    static char buffer[1024]={0};
    int buflen = sizeof(buffer);
    int len, pos;
    if(NULL == filepath)
    {
        return NULL;
    }
    //根目录
    if('/' == filepath[0])
    {
        return filepath;
    }
    else
    {
        (void)memset(buffer, 0, buflen);
        //返回指针为buffer地址
        if(NULL == getcwd(buffer, buflen))
        {
            return NULL;
        }
        len = strlen(filepath);
        pos = strlen(buffer);
        if((len + pos + 1) >= buflen)
        {
            return NULL;
        }
        buffer[pos] = '/';
        (void)memcpy(&buffer[pos+1], filepath, len);
        return buffer;
    }
}

//读文件, 可以分多次读
int sys_getfile(char* filename, char* buffer, size_t size, size_t* len)
{
    size_t ret;
    static FILE* fp = NULL;
    if(NULL == buffer)
    {
        *len = 0;
        return -1;
    }
    if(NULL == fp)
    {
        if(NULL == filename)
        {
            *len = 0;
            return -1;
        }
        fp = fopen(filename, "rb+");
        if(NULL == fp)
        {
            *len = 0;
            return -1;
        }
    }
    
    ret = fread(buffer, 1, size, fp);
    if(ret < size)
    {
        fclose(fp);
        fp = NULL;
    }
    *len = ret;
    
    return 0;
}

//写文件,支持追加写, len 非0表示没写完, 0表示已经写完了
int sys_putfile(char* filename, char* buffer, size_t len)
{
    size_t ret = 0;
    static FILE* fp = NULL;
    
    if(NULL == filename || NULL == buffer || 0 == len)
    {
        if(fp)
        {
            fclose(fp);
            fp = NULL;
        }
        
        return 0;
    }
    
    if(NULL == fp)
    {
        fp = fopen(filename, "ab+");
        if(NULL == fp)
        {
            return -1;
        }
    }
    
    do
    {
        ret += fwrite(&buffer[ret], 1, len, fp);
    }while(ret != len);
    
    return 0;
}

int sys_chdir(char* dir)
{
    int len, pos, buflen;
    char buffer[1024]={0};
    if(NULL == dir || '\0' == dir[0])
    {
        return -1;
    }
    buflen = sizeof(buffer);
    len = strlen(dir);
    if(len >= buflen)
    {
        return -1;
    }
    //根目录
    if('/' == dir[0])
    {
        if(chdir(dir) < 0)
        {
            return -1;
        }
    }
    else
    {
        //返回指针为buffer地址
        if(NULL == getcwd(buffer, buflen))
        {
            return -1;
        }
        //printf("sys_chdir %s\n", buffer);
        //printf("sys_chdir ptr:%p, %s\n", ptr, ptr);
        //printf("sys_chdir buffer:%p, %s\n", buffer, buffer);
        pos = strlen(buffer);
        if((len + pos + 1) >= buflen)
        {
            return -1;
        }
        buffer[pos] = '/';
        (void)memcpy(&buffer[pos+1], dir, len);
        //printf("sys_chdir %s\n", buffer);
        if(chdir(buffer) < 0)
        {
            return -1;
        }
    }
    
    return 0;
}

int test_copyfile()
{
    size_t ret;
    size_t len;
    char buffer[4096];
    char* filepath;
    int buflen = sizeof(buffer);
    filepath = sys_filepath("openssl-OpenSSL_1_0_2u.tar.gz");
    do
    {
        ret = sys_getfile(filepath, buffer, buflen, &len);
        if(ret < 0)
        {
            return -1;
        }
        ret = sys_putfile("test.tgz", buffer, len);
        if(ret < 0)
        {
            break;
        }
    }while(len == buflen);
    
    (void)sys_putfile(NULL, NULL, 0);
    return ret;
}

int main(int argc, char **argv)
{
    char* ptr;
    int ret, sockfd;
    struct sockaddr_in my_addr, their_addr;
    int reuse = 1;
    
    if(argc != 2)
    {
        printf("argc: %d error", argc);
        return -1;
    }
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("socket error");
        return -1;
    }
    int myport = atoi(argv[1]);
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
    if (argv[2])
    {
        my_addr.sin_addr.s_addr = inet_addr(argv[2]);
    }
    else
    {
        my_addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,(const void *)&reuse , sizeof(int));
    
    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1)
    {  
       printf("bind error\n");
       return -1;
    }
    
    if (listen(sockfd, 5) == -1)
    {
        printf("listen error\n");
        return -1;
    }
    
    cssl_init();
    cssl* ssl = cssl_server_open();
    if(NULL == ssl)
    {
        close(sockfd);
        return -1;
    }
    
    cssl_set_ca(ssl, "./ca.crt");
    cssl_set_cert(ssl, "./server.crt");
    cssl_set_key(ssl, "./server.key", ""); //需要在证书设置之后设置
    cssl_set_cipher(ssl,"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    
    while(1)
    {
        int len = sizeof(struct sockaddr);
        int new_fd;
        /* 等待客户端连上来 */
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len)) == -1)
        {
          printf("accept error\n");
          close(sockfd);
          cssl_close(ssl);
          return -1;
        }
        
        cssl_set_fd(ssl, new_fd);
        cssl_accept(ssl);
        
        while(1)
        {
            ret = sys_execute(ssl);
            if(ret < 0)
            {
                break;
            }
        }
    }
    
    close(sockfd);
    cssl_close(ssl);
    
    return 0;
}


