/****************************
FileName:head.h
Author:Qingqing Liang
Function:define the types of the variables and declare the functions
****************************/
#ifndef _HEAD_H
#define _HEAD_H
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define uint_32 unsigned int
#define uint_16 unsigned short
#define uint_8 unsigned char
#define PROTOCOL_IP  0x0008
#define PROTOCOL_ARP 0x0608
#define PROTOCOL_TCP 0x06
#define PROTOCOL_UDP 0x11
#define FLAG_SYN 0x02
#define FLAG_SYN_ACK 0x12
#define FLAG_ACK 0x10
#define TOTAL_FLOW_SIZE sizeof(total_flow)
#define HEAD_FLAG 0
/**********************
define the PCAP IP TCP UDP header
***************************/
typedef struct Packet_Header{   
	uint_32 sec;
	uint_32 millsec;
	uint_32 pcap_len;
	uint_32 packet_len;
}head_tag;
typedef struct Packet_Ip_Header{
	uint_8 version_headlen;
	uint_8 tos;
	uint_16 total_length;
	uint_16 identification;
	uint_16 flag_fragment;
	uint_8 ttl;
	uint_8 protocol;
	uint_16 checksum;
	uint_32 src_ip;
	uint_32 des_ip;
}ip_tag;
typedef struct Packet_TCP_Header{
	uint_16 src_port;
	uint_16 des_port;
	uint_32 sequence;
	uint_32 ack_seq;
	uint_8 head_len;
	uint_8 flags;
	uint_16 windows;
	uint_16 checksum;
	uint_16 urgenpoint;

}tcp_tag;
typedef struct Packet_UDP_header{
	uint_16 src_port;
	uint_16 des_port;
	uint_16 length;
	uint_16 checksum;
}udp_tag;
/********************************************
define the data structure used while analyzing the pcap file
********************************************/
typedef struct ServerNode{
	uint_32 sip;
	struct ServerNode *slc;
	struct ServerNode *src;
}servernode;
typedef struct ClientNode{
	uint_32 cip;
	uint_16 cport;
	struct ClientNode *clc;
	struct ClientNode *crc;

}clientnode;
typedef struct Address{
	uint_32 src_ip;
	uint_32 des_ip;
	uint_16 src_port;
	uint_16 des_port;
}address;
/*********************************************
define the data structure of storing the result 
of the statistic
*********************************************/
typedef struct TotalFlow{
	uint_32 sec;
	uint_32 packets;
	uint_32 bytes;
	struct TotalFlow *nextsec;
}total_flow;
typedef struct IptoIp{
     	uint_32 src;
     	uint_32 des;
	uint_32 packets;
	uint_32 bytes;
	struct IptoIp *nextip;
}iptoip;
typedef struct TimeDelay{
	struct Address add;
	int flag;
	uint_32 sec_f;
	uint_32 millsec_f;
	uint_32 sec_s;
	uint_32 millsec_s;
	struct TimeDelay *nextDelay;	
}timedelay;
typedef struct Service{
	uint_32 clientnum;
	uint_32 servernum;
	servernode *pserver;
	clientnode *pclient;
	uint_32 udpclientnum;
	uint_32 udpservernum;
	servernode *udppserver;
	clientnode *udppclient;
}service;
/**************************************
declare the functions 
changeseq_l():change the byte_sequence of long type of 32bit
changeseq_s():change the byte_sequence of short type of 16bit
getConfigValue():Analysis the config.ini and get the information 
		abount the database 
dboperation():All the database operations are here 
		It will put the result of the statistic into the mysql
***************************************/
uint_32 changeseq_l(uint_32 y);
uint_16 changeseq_s(uint_16 y);
int getConfigValue(char *szPath,char *szRoot,char *szAddress,char *szDb,char *szUser,char *szPasswd);
void getFileInfo(FILE *,total_flow *,int *,iptoip *,int,iptoip *,timedelay **,service *);
void dboperation(FILE *fp,char *szAddress,char *szDb,char *szUser,char *szPasswd);

#endif
