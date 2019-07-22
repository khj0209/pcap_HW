#include "pcap_func.h"
#include <cstdio>

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    int tcpIdx,dataIdx,dataSize;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(!checkL3type(&packet[0])) {//
            if(!checkL4type(&packet[ETH_SIZE])){
                tcpIdx=checkIpLength(&packet[ETH_SIZE]) + ETH_SIZE;
                dataIdx=checkTcpLength(&packet[tcpIdx]) + tcpIdx;
                dataSize=checkData(&packet[ETH_SIZE]);
                printMac(&packet[0]);
                printIp(&packet[ETH_SIZE]);
                printPort(&packet[tcpIdx]);
                printData(&packet[dataIdx],dataSize);
                printf("%u bytes captured\n\n", header->caplen);
            }
        }
    }
    pcap_close(handle);
    return 0;
}
