#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include "cssl.h"

// gcc client.c cssl.c -o client -lssl -lcrypto

//不支持的命令top,否则停不下来了
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

size_t sys_filesize(const char *filename)
{
    struct stat buf;
    if(stat(filename, &buf)<0)
    {
        return 0;
    }
    
    return buf.st_size;
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

//扩展数据单独处理
void* build_cmd(char* cmd)
{
    unsigned short type = 0; //shell
    char* ptr = cmd;
    unsigned int pos = 0;
    unsigned int len = 0;
    size_t extlen = 0;
    unsigned short typelen;
    if(NULL == cmd)
    {
        return NULL;
    }
    len = strlen(cmd);
    if('\n' == cmd[len])
    {
        cmd[len] = '\0';
    }
    while('\0' != *ptr)
    {
        ptr++;
        if(' ' == *ptr || '\t' == *ptr)
        {
            break;
        }
    }
    
    typelen = strlen(cmd) + 1;
    if(0 == strncmp("get", cmd, ptr-cmd))
    {
        type = 1;
        typelen = strlen(ptr+1)+1;
    }
    
    if(0 == strncmp("put", cmd, ptr-cmd))
    {
        type = 2;
        typelen = strlen(ptr+1)+1;
        extlen = sys_filesize(ptr+1);
    }
    
    if(0 == strncmp("cd", cmd, ptr-cmd))
    {
        type = 3;
        typelen = strlen(ptr+1)+1;
    }
    
    mycmd* cmdptr = (mycmd*)malloc(sizeof(mycmd) + typelen);
    if(NULL == cmdptr)
    {
        printf("build_cmd malloc error : %s\n", cmdptr);
        return NULL;
    }
    
    cmdptr->type = type;
    cmdptr->typelen = typelen;
    cmdptr->extlen = extlen;
    if(0 == type)
    {
        (void)memcpy(cmdptr->data, cmd, typelen);
    }
    else
    {
        (void)memcpy(cmdptr->data, ptr+1, typelen);
    }
    
    return cmdptr;
}

int execute_cmd(cssl* ssl, char* cmdline)
{
    size_t filesize, extlen, len;
    int headsize, ret, pos;
    char filepath[1024];
    mycmd reccmd;
    char* filepathname;
    unsigned char* pcmd;
    char recvbuffer[4096];
    int bufflen = sizeof(recvbuffer);
    (void)memset(recvbuffer, 0, bufflen);
    //解析命令行并构造命令头
    mycmd* cmd = build_cmd(cmdline);
    pcmd = (unsigned char*)cmd;
    
    if(2 == cmd->type) //put,需要加文件长度
    {
        //保存文件名
        (void)memcpy(filepath, cmd->data, cmd->typelen);
        //获取文件完整路径
        filepathname = sys_filepath(filepath);
        //获取文件大小
        extlen = sys_filesize(filepathname);
        cmd->extlen = extlen;
        
    }
    
    //写命令头
    headsize = sizeof(mycmd) + cmd->typelen;
    pos = 0;
    do
    {
        ret = cssl_write(ssl, &pcmd[pos], headsize-pos);
        if(ret < 0)
        {
            free(cmd);
            return -1;
        }
        pos += ret;
    }while(pos < headsize);
    
    headsize = sizeof(mycmd);
    //特殊处理
    if(0 == cmd->type) //shell, 接收返回数据并打印
    {
        //接收数据头
        pos = 0;
        do
        {
            ret = cssl_read(ssl, &recvbuffer[pos], headsize-pos);
            if(ret < 1)
            {
                free(cmd);
                return -1;
            }
            pos += ret;
        }while(pos < headsize);
        (void)memcpy(&reccmd, recvbuffer, headsize);
        extlen = reccmd.extlen;
        
        //接收命令行结果
        filesize = 0;
        do
        {
            ret = cssl_read(ssl, recvbuffer, bufflen-1);
            if(ret < 1)
            {
                free(cmd);
                return -1;
            }
            recvbuffer[ret] = '\0';
            printf("%s", recvbuffer);
            filesize += ret;
        }while(filesize < extlen);
    }
    else if(1 == cmd->type) //get, 读取并保存文件
    {
        //接收数据头
        pos = 0;
        do
        {
            ret = cssl_read(ssl, &recvbuffer[pos], headsize-pos);
            if(ret < 1)
            {
                free(cmd);
                return -1;
            }
            pos += ret;
        }while(pos < headsize);
        (void)memcpy(&reccmd, recvbuffer, headsize);
        extlen = reccmd.extlen; //获取文件大小
        
        //返回中typelen为0,没有文件名,使用输入解析的文件名
        (void)memcpy(filepath, cmd->data, cmd->typelen);
        //获取文件完整路径
        filepathname = sys_filepath(filepath);
        
        //读取文件内容并保存文件
        filesize = 0;
        do
        {
            ret = cssl_read(ssl, recvbuffer, bufflen);
            if(ret < 1) //0代表断开
            {
                printf("get read error : %s\n", filepathname);
                (void)sys_putfile(NULL, NULL, 0);
                free(cmd);
                return -1;
            }
            filesize += ret;
            
            //写文件
            ret = sys_putfile(filepathname, recvbuffer, ret);
            if(ret < 0)
            {
                printf("get write file error : %s\n", filepathname);
                (void)sys_putfile(NULL, NULL, 0);
                free(cmd);
                return -1;
            }
        }while(filesize < extlen);
        
        (void)sys_putfile(NULL, NULL, 0);
        printf("get %s completed\n", filepathname);
    }
    else if(2 == cmd->type) //put, 发送文件,无需接收
    {
        if(extlen > 0)
        {
             //printf("put %s start, len: %llu\n", filepathname, extlen);
            //发送文件
            filesize = 0;
            do
            {
                ret = sys_getfile(filepathname, recvbuffer, bufflen, &len);
                if(ret < 0)
                {
                    free(cmd);
                    printf("put read file error : %s\n", filepathname);
                    return -1;
                }
                filesize += len;
                
                pos = 0;
                do
                {
                    ret = cssl_write(ssl, &recvbuffer[pos], len-pos);
                    if(ret < 0)
                    {
                        free(cmd);
                        printf("put write error : %s\n", filepathname);
                        return -1;
                    }
                    pos += ret;
                }while(pos < len);
                //printf("filesize : %llu\n", filesize);
            }while(filesize < extlen); //相等没有读完
            printf("put %s completed\n", filepathname);
        }
    }
    else if(3 == cmd->type) //cd, 已经完成
    {
        free(cmd);
        return 0;
    }
    else
    {
        free(cmd);
        return 0;
    }
    
    free(cmd);
    return 0;
}


int main(int argc, char **argv)
{
    int ret, sockfd;
    struct sockaddr_in dest;
    char buffer[1024];
    
    if(argc != 3)
    {
        printf("argc: %d error", argc);
        return -1;
    }
    
    cssl_init();
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("socket error");
        return -1;
    }
    
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0)
    {
        printf("ip error : %s\n", argv[1]);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0)
    {
        printf("connect error\n");
        close(sockfd);
        return -1;
    }  
    
    cssl* ssl = cssl_client_open();
    if(NULL == ssl)
    {
        close(sockfd);
        return -1;
    }
    
    cssl_set_ca(ssl, "./ca.crt");
    cssl_set_cert(ssl, "./server.crt");
    //cssl_set_key(ssl, "./server.key", "");
    cssl_set_cipher(ssl,"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    cssl_set_fd(ssl, sockfd);
    ret = cssl_connect(ssl);
    if(-1 == ret)
    {
        close(sockfd);
        cssl_close(ssl);
        return -1;
    }
    
    (void)memset(buffer, 0, sizeof(buffer));
    while(fgets(buffer, sizeof(buffer), stdin))
    {
        int len = strlen(buffer);
        buffer[len-1] = '\0';
        execute_cmd(ssl, buffer);
        (void)memset(buffer, 0, sizeof(buffer));
    }
    
    close(sockfd);
    cssl_close(ssl);
    
    return 0;
}


