#pragma once
#include<pcap.h>
#define ETH_SIZE 14

int checkL3type(const u_char* pack);
int checkL4type(const u_char* pack);
int checkIpLength(const u_char* pack);
int checkTcpLength(const u_char* pack);
int checkData(const u_char* pack);
void printMac(const u_char* packet);
void printIp(const u_char* packet);
void printPort(const u_char* packet);
void printData(const u_char* packet,int dataSize);
