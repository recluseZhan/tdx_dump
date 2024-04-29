#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#define DEVNAME "/dev/dump_dev"
#include <sys/types.h>

void main(){
    //unsigned char a[20]="hello,world!thiswork";
    //printf("%lx\n",a);
    int fd = 0;
    pid_t pid=getpid();

    unsigned long pp[3]={pid,&main,1};
    //for(int i=0;i<4096;i++){
        //pp[1] = &main+i;
        fd = open(DEVNAME,O_RDWR);
        printf("fd:%d\n",fd);
        read(fd,pp,sizeof(pp));
        close(fd);  
    //}
    //getchar();
    //fd = open(DEVNAME,O_RDWR);
    //printf("fd:%d\n",fd);
    //write(fd,pp,sizeof(pp));
    //close(fd);  
    return 0;
}
