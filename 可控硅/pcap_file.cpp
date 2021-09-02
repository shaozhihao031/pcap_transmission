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
