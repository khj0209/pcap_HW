#include "pcap_func.h"

int checkL3type(const u_char* pack){
    if(pack[12]==0x08&&pack[13]==0x00) return 0;
    else return -1;
}
int checkL4type(const u_char* pack){
    if(pack[9]==0x06) return 0;
    else return -1;
}
int checkIpLength(const u_char* pack){
    if((pack[0]%16)>5) return (pack[0]%16) * 4;
    else return 20;
}
int checkTcpLength(const u_char* pack){
    if((pack[12]/16)>5) return (pack[12]/16) * 4;
    else return 20;
}
int checkData(const u_char* pack){
    int ipLength = checkIpLength(pack);
    int tcpLength = checkTcpLength(&pack[ipLength]);
    return pack[2] * 256 + pack[3] - ipLength - tcpLength;
}

void printMac(const u_char* packet){
    printf("Source Mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
    printf("Destination Mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
}
void printIp(const u_char* packet){
    printf("Source IP : %d.%d.%d.%d\n",
           packet[12],packet[13],packet[14],packet[15]);
    printf("Destination IP : %d.%d.%d.%d\n",
           packet[16],packet[17],packet[18],packet[19]);
}
void printPort(const u_char* packet){
    printf("Source Port : %u\n", (packet[0] << 8) | packet[1]);
    printf("Destination Port : %u\n", (packet[2] << 8) | packet[3]);
}
void printData(const u_char* packet,int dataSize){
    int n = dataSize;
    if(n>10) n = 10;
    printf("Data : ");
    for (int i = 0;i < n;i++){
        printf("%02X ",packet[i]);
    }
    printf("\n");
}
