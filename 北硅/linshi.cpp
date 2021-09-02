#include<pcap.h>
#include<time.h>
#include<stdlib.h>
#include<stdio.h>
//现在的状态是写入一个数据包的，如果要分别符合要求总大小，包数量，时间等
//就用一个死循环，分别用一个size_sum count cycle_time 来进行控制
//总大小到预定值则刷新，数量到则刷新，时间到了也刷新（与文件中第一个包头比较，或者直接在刷新的时候记录一个结束时间（起始时间加上循环时间=结束时间））
/*typedef struct timeval{
 guint32 ts_sec;         
        guint32 ts_usec;

}*/
typedef struct pcaprec_hdr_s {
        bpf_u_int32 ts_sec;         /* timestamp seconds */
        bpf_u_int32 ts_usec;        /* timestamp microseconds */
        bpf_u_int32 incl_len;       /* number of octets of packet saved in file */
        bpf_u_int32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
// 返回自系统开机以来的毫秒数（tick）

 unsigned long GetTickCount()
 {   
     struct timespec ts;
         
         clock_gettime(CLOCK_MONOTONIC, &ts);
             
             return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
             }


//
void getPacket(u_char* arg,const struct pcap_pkthdr* pkthdr ,const u_char* packet){
        int *id=(int *) arg;
        int len=pkthdr->len;
        char* ls[len];
//      char *ls[1500]={0};

        FILE* fp;
        fp=fopen("pcap1.pcap","a" );

        printf("测试：%d\n ",pkthdr->len);
        printf("测试：%d\n",len);
        printf("测试：%d\n",strlen(ls));

        PcapWriteDataHead2(fp,len,len);

        if (1 != fwrite(packet, len, 1, fp))
        {
                printf("write data err\n");
                return (-1);
        }
        fclose(fp);
}/*
int PcapWriteDataHead(FILE* fp,int caplen,int len) as{
 struct pcap_pkthdr  h;
          struct timeval tv;
          //填充头部信息 
        struct pcaprec_hdr_s h;
        gettimeofday(&tv,NULL);//获取1970-1-1到现在的时间结果保存到tv中
        h.ts.tv_sec =2333; //GetTickCount();  //获得当前时间，只是用于填充，对于文件本身没有影响
        h.ts.tv_usec =2333; // GetTickCount();
        h.caplen = len;
        h.len = len;   //这两个成员可以赋一样的值，即得到的数据包的长度

        printf("%d",h.len);
        printf("%d",h.caplen);
        printf("%d",sizeof(h));
        printf("%x",h);

//printMsg(h);
        if (fwrite((char*)&h, sizeof(h), 1, fp) != 1)
                        return 0;

                        return 1;
                        }
*/
int PcapWriteDataHead2(FILE* fp,int caplen,int len){
        int seconds = time((time_t*)NULL);
        struct pcaprec_hdr_s h;
        struct timeval tv;
        //填充头部信息
        gettimeofday(&tv,NULL);//获取1970-1-1到现在的时间结果保存到tv中
        h.ts_sec =seconds; //GetTickCount();  //获得当前时间，只是用于填充，对于文件本身没有影响
        h.ts_usec =seconds; // GetTickCount();
        h.incl_len = len;
        h.orig_len = len;   //这两个成员可以赋一样的值，即得到的数据包的长度


        if (fwrite((char*)&h, sizeof(h), 1, fp) != 1)
                return 0;

return 1;
}
int PcapWriteHead(FILE *fp, int linktype, int thiszone, int snaplen)
{
        struct pcap_file_header hdr;     //声明一个pcap_file_header 对象

        hdr.magic = 0xa1b2c3d4;
        hdr.version_major = PCAP_VERSION_MAJOR;
        hdr.version_minor = PCAP_VERSION_MINOR;   //固定填充

        hdr.thiszone = thiszone;
        hdr.snaplen = snaplen;
        hdr.sigfigs = 0;
        hdr.linktype = linktype;
 if (fwrite((char*)&hdr, sizeof(hdr), 1, fp) != 1)  return 0;


        return 1;
}
int main(){
char errBuf[PCAP_ERRBUF_SIZE], *devStr;

/*获取接口*/

devStr =pcap_lookupdev(errBuf);

if(devStr){
printf("succes:device:%s\n",devStr);

}
else {
printf("error:%s\n",errBuf);
exit(1);
}

/*打开一个终端直到接收到一个包*/
pcap_t *device =pcap_open_live(devStr ,65535,1,0,errBuf);

if(!device){
printf("error:pcap_open_live():%s\n",errBuf);
exit(1);
}

/*等待一个包 */

struct pcap_pkthdr packet;
const u_char *pktStr= pcap_next(device,&packet);

printf("包大小：%d\n ",packet.len);
printf("字节数：%d\n ",packet.caplen);
printf("抓取时间：%s \n ",ctime((const time_t *)&packet.ts.tv_sec));
/*
char  *fp[50];
printf("输入文件名：");
        int i;
scanf("%s", fp);*/

        FILE* fp;
        fp=fopen("pcap1.pcap","w" );
        PcapWriteHead(fp,1,8,65535);
        int id=0;
        fclose(fp);

pcap_loop(device,3,getPacket,(u_char*)&id);
pcap_close(device);
return 0;
  if (fwrite((char*)&hdr, sizeof(hdr), 1, fp) != 1)  return 0;


        return 1;
}
int main(){
char errBuf[PCAP_ERRBUF_SIZE], *devStr;

/*获取接口*/

devStr =pcap_lookupdev(errBuf);

if(devStr){
printf("succes:device:%s\n",devStr);

}
else {
printf("error:%s\n",errBuf);
exit(1);
}

/*打开一个终端直到接收到一个包*/
pcap_t *device =pcap_open_live(devStr ,65535,1,0,errBuf);

if(!device){
printf("error:pcap_open_live():%s\n",errBuf);
exit(1);
}

/*等待一个包 */

struct pcap_pkthdr packet;
const u_char *pktStr= pcap_next(device,&packet);

printf("包大小：%d\n ",packet.len);
printf("字节数：%d\n ",packet.caplen);
printf("抓取时间：%s \n ",ctime((const time_t *)&packet.ts.tv_sec));
/*
char  *fp[50];
printf("输入文件名：");
        int i;
scanf("%s", fp);*/

        FILE* fp;
        fp=fopen("pcap1.pcap","w" );
        PcapWriteHead(fp,1,8,65535);
        int id=0;
        fclose(fp);

pcap_loop(device,3,getPacket,(u_char*)&id);
pcap_close(device);
return 0;
}
