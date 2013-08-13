/********************************************************
File Name:pcapanalysis.c
Author:Qingqing Liang
Description:This file include the implemention of the functions
of analyzing the PCAP file and return the result of the statistic.
And list the main function here:

total flow analysis
 total_flow* totalflow(total_flow *tf,head_tag *phead,int *s);

ip to ip flow analysis
void iptoipflow(iptoip *itemsip,iptoip *ipflag,head_tag *phead,ip_tag *iphead);

timedelay analysis
void gettimedelay(head_tag *phead,ip_tag *iphead,tcp_tag *tcphead,timedelay **punhandled,timedelay **phandled,int *psyn_num,int *psyn_ack_num);

service analysis
int ClientIsIn(clientnode **root,uint_32 newip,uint_16 newport);

********************************************************/


#include "head.h"
#define PCAP_LEN 24L
#define PACKET_HEAD_LEN sizeof(head_tag)
#define CLIENT_SIZE sizeof(clientnode)
#define SERVER_SIZE sizeof(servernode)

uint_16 changeseq_s(uint_16 y)
{
	uint_16 temp;
	temp=y&255;
	y=y>>8;
	temp=temp<<8;
	y=y|temp;
	return y;
}

uint_32 changeseq_l(uint_32 y){
	uint_32 temp3;
	uint_32 temp2;
	uint_32 temp1;
	temp3=y&0xFF0000;
	temp2=y&0xFF00;
	temp1=y&0xFF;
	y=y>>24;
	temp3=temp3>>8;
	temp2=temp2<<8;
	temp1=temp1<<24;
	y=y|temp3|temp2|temp1;
	return y;
}
 static clientnode * NewClientNode(uint_32 newip,uint_16 newport){
	clientnode *temp;
	temp=(clientnode *)malloc(CLIENT_SIZE);	
	memset(temp,0,CLIENT_SIZE);
	temp->cip=newip;
	temp->cport=newport;	
	return temp;

}
static servernode * NewServerNode(uint_32 newip){
	servernode *temp;
	temp=(servernode *)malloc(SERVER_SIZE);
	memset(temp,0,SERVER_SIZE);
	temp->sip=newip;
	return temp;

}
/**********************************************************************
function:try to find if the new server is in the Tree.
If in return -1;
If not ,return 1;
root:the pointer to the Sorted Tree storing the server that already has been calculated.
newip:the ip address of the  server
*********************************************************************/
static int ServerIsIn(servernode **root,uint_32 newip){
	servernode *oncmp;
	if(*root==NULL){
		*root=NewServerNode(newip);
		return 1;
	}
	oncmp=*root;	
	while(1){
		if(newip<oncmp->sip){
			if(oncmp->slc!=NULL){
				oncmp=oncmp->slc;
				continue;
			}
			oncmp->slc=NewServerNode(newip);
			return 1;
		}
		if(newip==oncmp->sip)
			return -1;
		if(newip>oncmp->sip){
			if(oncmp->src!=NULL){
				oncmp=oncmp->src;
				continue;
			}
			oncmp->src=NewServerNode(newip);
			return 1;
		}
}
}



/**********************************************************************
function:try to find if the new client is in the Tree.
If in return -1;
If not ,return 1;
root:the pointer to the Sorted Tree storing the client that already has been calculated.
newip:the ip address of the  clinet
newport: the  source port of the  client
*********************************************************************/
static int ClientIsIn(clientnode **root,uint_32 newip,uint_16 newport){
	clientnode *oncmp;
	int i;
	if(*root==NULL)
		i=-1;
	else 
		i=1;
	if(*root==NULL){	
		*root=NewClientNode(newip,newport);
		return 1;
	}
	oncmp=(*root);
	while(1){	
		if(newip<oncmp->cip){
			if(oncmp->clc!=NULL){
				oncmp=oncmp->clc;
				continue;
			}
			oncmp->clc=NewClientNode(newip,newport);
			return 1;
			
		}//1
		if(newip==oncmp->cip){//2
			if(newport<oncmp->cport){
				if(oncmp->clc!=NULL){
					oncmp=oncmp->clc;
					continue;
				}
				oncmp->clc=NewClientNode(newip,newport);
				return 1;
			}
			if(newport==oncmp->cport){
				return -1;
			}
			if(newport>oncmp->cport){
				if(oncmp->crc!=NULL){
					oncmp=oncmp->crc;
					continue;
				}
				oncmp->crc=NewClientNode(newip,newport);
				return 1;
			}



		}//2
		if(newip>oncmp->cip){//3
			if(oncmp->crc!=NULL){
				oncmp=oncmp->crc;
				continue;
			}
			oncmp->crc=NewClientNode(newip,newport);
			return 1;
		}//3
	}//4
}


void freeNode(clientnode** root){
	if(*root!=NULL){
		clientnode *ln=(*root)->clc;
		clientnode *rn=(*root)->crc;
		free(*root);
		*root=NULL;
		freeNode(&ln);
		freeNode(&rn);
	}
	return;
}
void freeNodeS(servernode** root){
	if(*root!=NULL){
		servernode *ln=(*root)->slc;
		servernode *rn=(*root)->src;
		free(*root);
		*root=NULL;
		freeNodeS(&ln);
		freeNodeS(&rn);
	}
	return;
}

/******************************************************************
function:get the totalflow of the IPv4 per seconds
return the link of the last node
tf:point to the last node of the link
head_tag:the pcap header of the packets
s:point to the num of the second
******************************************************************/
static total_flow* totalflow(total_flow *tf,head_tag *phead,int *s){
		if(tf->sec==phead->sec){
			++(tf->packets);
			tf->bytes+=phead->packet_len;
		}
		else if(tf->sec!=phead->sec){
			total_flow *tf_temp;
			uint_32 j=tf->sec+1;
			if(tf->sec==HEAD_FLAG)
				j=phead->sec;
			for(;j<=phead->sec;j++){
				++*s;
				tf_temp=(total_flow *)malloc(TOTAL_FLOW_SIZE);
				memset(tf_temp,0,TOTAL_FLOW_SIZE);
				tf_temp->sec=j;
				tf_temp->nextsec=NULL;
				if(j==phead->sec){
					tf_temp->packets=1;
					tf_temp->bytes=phead->packet_len;
				}
				tf->nextsec=tf_temp;
				tf=tf_temp;
			}
		}
		return tf;

}
static void InsertToChain(iptoip *pb,iptoip *pn,uint_32 src,uint_32 des,head_tag *phead){
	
	iptoip *newip;
	do
	{
		if(src<pn->src){
					
			newip=(iptoip *)malloc(sizeof(iptoip));
			memset(newip,0,sizeof(iptoip));
			newip->src=src;
			newip->des=des;
			newip->packets=1;
			newip->bytes=phead->packet_len;
			newip->nextip=pn;
			pb->nextip=newip;
			break;
			
		}
		if(src==pn->src){
			if(des<pn->des){
				newip=(iptoip *)malloc(sizeof(iptoip));
				memset(newip,0,sizeof(iptoip));
				newip->src=src;
				newip->des=des;
				newip->packets=1;
				newip->bytes=phead->packet_len;
				newip->nextip=pn;
				pb->nextip=newip;
				break;
			}
			if(des==pn->des){
				++pn->packets;
				pn->bytes+=phead->packet_len;
				break;
			}
			if(des>pn->des){
				if(pn->nextip==NULL){
					newip=(iptoip *)malloc(sizeof(iptoip));
					memset(newip,0,sizeof(iptoip));
					newip->src=src;
					newip->des=des;
					newip->packets=1;
					newip->bytes=phead->packet_len;
					newip->nextip=NULL;
					pn->nextip=newip;
					break;
					
			
				}
				pb=pn;
				pn=pn->nextip;
				continue;
			}	
		}
		if(src>pn->src){
			if(pn->nextip==NULL){
				newip=(iptoip *)malloc(sizeof(iptoip));
				memset(newip,0,sizeof(iptoip));
				newip->src=src;
				newip->des=des;
				newip->packets=1;
				newip->bytes=phead->packet_len;
				newip->nextip=NULL;
				pn->nextip=newip;
				break;
			}
			pb=pn;
			pn=pn->nextip;
			continue;
		}
		
	 }while(1);
}
/******************************************************************************
function:get the ip to ip flow
itemsip:Array head of the store of the flow
ipflag:the new node of the package information
phead: the pcap header of the current package
iphead: the ip header of the current package
***************************************************************************/
void iptoipflow(iptoip *itemsip,iptoip *ipflag,head_tag *phead,ip_tag *iphead){

	uint_16 lowip;
	uint_16 highip;
	uint_16 items;
	iptoip *pnext=NULL;
	iptoip *pbefore=NULL;

	lowip=iphead->src_ip>>24;
	highip=iphead->des_ip>>24;
	items=lowip*highip;
	if(itemsip[items].nextip==NULL){ //2
		itemsip[items].src=iphead->src_ip;
		itemsip[items].des=iphead->des_ip;
		itemsip[items].bytes+=phead->packet_len;
		itemsip[items].packets+=1;
		itemsip[items].nextip=ipflag;		
	}
	else if(itemsip[items].nextip==ipflag){   //3
		if(itemsip[items].src==iphead->src_ip&&itemsip[items].des==iphead->des_ip){//4
			itemsip[items].bytes+=phead->packet_len;
			itemsip[items].packets+=1;
		} //4
		else{
			pnext=(iptoip *)malloc(sizeof(iptoip));
			memset(pnext,0,sizeof(iptoip));
			pnext->src=iphead->src_ip;
			pnext->des=iphead->des_ip;
			pnext->bytes+=phead->packet_len;
			pnext->packets+=1;
			pnext->nextip=NULL;
			itemsip[items].nextip=pnext;
			pnext=NULL;
		}
	} 
	else{
		
		if(itemsip[items].src==iphead->src_ip&&itemsip[items].des==iphead->des_ip){//4
			itemsip[items].bytes+=phead->packet_len;
			itemsip[items].packets+=1;
		}
		 else{
			pnext=itemsip[items].nextip;
			pbefore=&itemsip[items];
			InsertToChain(pbefore,pnext,iphead->src_ip,iphead->des_ip,phead);
		}
	}

}

void JoinLink(timedelay* join,timedelay **head){
	timedelay *swap;
	timedelay *beforeswap;
	swap=*head;
	if(*head==NULL){
		*head=join;
		join->nextDelay=NULL;
		//printf("rm head\t");
		return;

	}
	while(1){
		if(join->add.src_ip<swap->add.src_ip){
		//	printf("rm small\t");
			if(swap==*head){
				join->nextDelay=*head;
				*head=join;
				return;
			}		
			beforeswap->nextDelay=join;
			join->nextDelay=swap;
			return;
		}
		else if(join->add.src_ip==swap->add.src_ip){
			if(join->add.des_ip<=swap->add.des_ip){
				if(swap==*head){
		//			printf("rm des<= head\t");
					join->nextDelay=*head;
					*head=join;
					return;
				}
		//		printf("rm des<= mid\t");
				beforeswap->nextDelay=join;
				join->nextDelay=swap;
				return;
			}	
			if(join->add.des_ip>swap->add.des_ip){
				if(swap->nextDelay==NULL){
					
					swap->nextDelay=join;
					join->nextDelay=NULL;
					return;
				}
				beforeswap=swap;
				swap=swap->nextDelay;
				continue;
			}

		}
		else if(join->add.src_ip>swap->add.src_ip){
			if(swap->nextDelay==NULL){
		//		printf("rm big\t");
				swap->nextDelay=join;
				join->nextDelay=NULL;
				return;
			}	
			beforeswap=swap;
			swap=swap->nextDelay;
			continue;
		}
	
	}

}
static int match(address *s,address *c){
	if(s->src_ip==c->des_ip&&s->des_ip==c->src_ip&&s->src_port==c->des_port&&s->des_port==c->src_port)
		return 0;
	return -1;
}
static int equal(address *s,address *c){
	if(s->src_ip==c->src_ip&&s->des_ip==c->des_ip&&s->src_port==c->src_port&&s->des_port==c->des_port)
		return 0;
	return -1;
} 
static void initdelay(timedelay *getinit,ip_tag* iphead,tcp_tag *tcphead,head_tag *packethead){
	getinit->add.src_ip=iphead->src_ip;
	getinit->add.des_ip=iphead->des_ip;
	getinit->add.src_port=tcphead->src_port;
	getinit->add.des_port=tcphead->des_port;
	getinit->flag=1;
	getinit->sec_f=packethead->sec;
	getinit->millsec_f=packethead->millsec;

}
static int JoinUnhandle(timedelay *join,timedelay **Unhead){
	timedelay *pb;
	timedelay *pn;
	if(*Unhead==NULL){
		(*Unhead)=join;
		join->nextDelay=NULL;
		//printf("first join\n");
		return 0;
	}
	pn=*Unhead;
	
	while(1){
		if(join->add.src_ip<pn->add.src_ip){
		//	printf("small join\n");
			if(pn==*Unhead){
				join->nextDelay=pn;
				*Unhead=join;
				return 0;
			}
			pb->nextDelay=join;
			join->nextDelay=pn;
			return 0;
			
		}
		if(join->add.src_ip==pn->add.src_ip){
			if(equal(&(join->add),&(pn->add))==0){
				
		//		printf("join failure\n");
				return -1;
			}
		//	printf("equla join\n");
			if(pn==*Unhead){
				join->nextDelay=pn;
				*Unhead=join;
				return 0;
			}
			pb->nextDelay=join;
			join->nextDelay=pn;
			return 0;

		}
		if(join->add.src_ip>pn->add.src_ip){
			if(pn->nextDelay==NULL){
		//		printf("big join\n");
				pn->nextDelay=join;
				join->nextDelay=NULL;
				return 0;
			}
			pb=pn;
			pn=pn->nextDelay;
			continue;
		}

				

	}
	return -1;
}
static int MatchUnhandle(ip_tag* ipinfo,tcp_tag* tcpinfo,head_tag *packetinfo,timedelay *Unhead){
	timedelay *temp;
	//printf("%u %u ",packetinfo->sec,packetinfo->millsec);
	if(Unhead==NULL)
		return -1;
	address merage;
	merage.src_ip=ipinfo->src_ip;
	merage.des_ip=ipinfo->des_ip;
	merage.src_port=tcpinfo->src_port;
	merage.des_port=tcpinfo->des_port;
	temp=Unhead;
	while(1){
		if(merage.des_ip<temp->add.src_ip)
			return -1;
		if(match(&(temp->add),&merage)==0){
			temp->sec_s=packetinfo->sec;
			temp->millsec_s=packetinfo->millsec;
			if(temp->millsec_s<temp->millsec_f){
				temp->millsec_f=(temp->millsec_s+1000000)-temp->millsec_f;
				temp->sec_f=temp->sec_s-temp->sec_f-1;
			}
			else{
				temp->millsec_f=(temp->millsec_s)-temp->millsec_f;
				temp->sec_f=temp->sec_s-temp->sec_f;	
			}
			temp->flag=2;
		//	printf("merage!\n");
			return 0;
		}
		if(temp->nextDelay==NULL)
			return -1;
		temp=temp->nextDelay;
	}
	
	return -1;
}
static int RemoveUnhandle(ip_tag* ipinfo,tcp_tag* tcpinfo,head_tag *packetinfo,timedelay **Unhead,timedelay **Handled){	
	timedelay *temp;
	timedelay *swap;
	uint_32 temps;
	uint_32 tempm;
	if(*Unhead==NULL)
		return -1 ;
	address merage;
	merage.src_ip=ipinfo->src_ip;
	merage.des_ip=ipinfo->des_ip;
	merage.src_port=tcpinfo->src_port;
	merage.des_port=tcpinfo->des_port;
	temp=*Unhead;
	while(1){
		if(merage.src_ip<temp->add.src_ip){
		//	printf("remove failure\n");
			return -1;
		}
		if(equal(&merage,&(temp->add))==0){
			temps=packetinfo->sec;
			tempm=packetinfo->millsec;
			if(tempm<temp->millsec_s){
				temp->millsec_s=(tempm+1000000)-temp->millsec_s;
				temp->sec_s=temps-temp->sec_s-1;
			}
			else{
				temp->millsec_s=tempm-temp->millsec_s;
				temp->sec_s=temps-temp->sec_s;
			}
			temp->flag=3;
			if(temp==*Unhead){
				*Unhead=temp->nextDelay;
				
			}
			else{
				swap->nextDelay=temp->nextDelay;
			}
			
		//	printf("%x %x yesremove\n",temp->add.src_ip,temp->add.des_ip);
				
			JoinLink(temp,Handled);
	/*		temp->nextDelay=*Handled;
			*Handled=temp;*/

			return 0;
		}	
		if(temp->nextDelay==NULL){
		//	printf("remove bad fail\n");
			return -1;
		}
		swap=temp;
		temp=temp->nextDelay;

	}
}

/******************************************************************
function:get the timdelay of the ip to ip
phead:the pcap header of the current package
iphead:the ip header of the current package
tcphead:the tcp header of the current package
punhadled: point to the point of the unhandled link
phandled:point to the point of the handled link
psyn_num:point to the num of the syn package 
psyn_ack_num:point to the nun of the syn_ack package
******************************************************************/
void gettimedelay(head_tag *phead,ip_tag *iphead,tcp_tag *tcphead,timedelay **punhandled,timedelay **phandled,int *psyn_num,int *psyn_ack_num){
		timedelay *temp=NULL;		
		if(tcphead->flags==FLAG_SYN){
			temp=(timedelay *)malloc(sizeof(timedelay));
			memset(temp,0,sizeof(timedelay));
			initdelay(temp,iphead,tcphead,phead);		
			if(JoinUnhandle(temp,punhandled)==0){
				++*psyn_num;		
			}	
		        return;
		}
		
		if(tcphead->flags==FLAG_SYN_ACK&&(*psyn_num)>0){
			if(MatchUnhandle(iphead,tcphead,phead,*punhandled)==0){
				++*psyn_ack_num;
			}
			return;	
		}
		if(tcphead->flags==FLAG_ACK&&*psyn_ack_num>0){
			if(RemoveUnhandle(iphead,tcphead,phead,punhandled,phandled)==0){
				--*psyn_num;
				--*psyn_ack_num;
			}
			return;
			
		}
}
void del_unhandled(timedelay *un){
	timedelay *swap;
	timedelay *swap_next;
	swap=un;
	while(swap!=NULL){
		swap_next=swap->nextDelay;
		free(swap);
		swap=swap_next;		
	}
	un=NULL;
	swap=NULL;
	swap_next=NULL;
}
void handled_merage(timedelay *handled){
	timedelay *swap=handled;
	timedelay *swap_next;
	int count=1;
	while(swap!=NULL){
		if(swap->nextDelay==NULL)
			break;
		swap_next=swap->nextDelay;
		if(swap->add.src_ip==swap_next->add.src_ip&&swap->add.des_ip==swap_next->add.des_ip){
			swap->sec_f+=swap_next->sec_f;
			swap->millsec_f+=swap_next->millsec_f;
			swap->sec_s+=swap_next->sec_s;
			swap->millsec_s+=swap_next->millsec_s;
			swap->nextDelay=swap_next->nextDelay;
			count++;
			free(swap_next);
			continue;
		}
			
		/*handle the sec*/
		uint_32 sectemp;
		sectemp=swap->sec_f%count;
		swap->sec_f=(swap->sec_f-sectemp)/count;
		swap->millsec_f/=count;
		swap->millsec_f+=sectemp/count*1000000;
		sectemp=swap->sec_s%count;
                swap->sec_s=(swap->sec_s-sectemp)/count;
                swap->millsec_s/=count;
                swap->millsec_s+=sectemp/count*1000000;
		swap=swap->nextDelay;
		count=1;
	}
}

/************************************
function:the interface to the outside
fp: the pcap file pointer
tf_head:the link header point of the total flow 
s:point to the num of the seconds
itemsip:the array header the stroing
num:size fo the array of ip to ip flow
ptimedelay_head:the pointer the pointer of the timdelay linker header
pservice:header of the array 
******************************/
void getFileInfo(
	FILE *fp,
	total_flow *tf_head,int *s,
	iptoip *itemsip,int num,iptoip *temp,
	timedelay **ptimedelay_head,
	service *pservice
	)
{	
	fseek(fp,PCAP_LEN,SEEK_SET);
        head_tag packet_head;
	uint_16 type;
	ip_tag packet_ip;			
	tcp_tag segment_tcp;
	udp_tag datagrame_udp;
	uint_8 ipheadlen;
	uint_32 unread_tcp;
	uint_32 unread_udp;

	/*total flow init begin*/
	total_flow *tf=tf_head;
	/*total flow init end*/
	
	/*iptoip flow init begin*/
	memset(itemsip,0,num*sizeof(iptoip));
	/*iptoip flow init end*/
	
	/*timedelay init begin*/
	timedelay *unhandled=NULL;
	timedelay *handled=NULL;
	uint_32 syn_num=0;
	uint_32 syn_ack_num=0;
	/*timedelay init end*/

	/*service init begin*/
	uint_16 porttemp,portswap;
	/*service init end*/	
	
	while(1){
		if(fread(&packet_head,PACKET_HEAD_LEN,1,fp)!=1)
			break;
		
		fseek(fp,12L,1);
		fread(&type,sizeof(uint_16),1,fp);
		if(type!=PROTOCOL_IP){
			fseek(fp,packet_head.pcap_len-14,1);
			continue;
		}
		/*total flow operation begin*/
		tf=totalflow(tf,&packet_head,s);		
		/*total flow operation end*/

		fread(&packet_ip,sizeof(ip_tag),1,fp);
		/*iptoip flow operation begin*/
		iptoipflow(itemsip,temp,&packet_head,&packet_ip);
		/*iptoip flow operation end*/
		if(packet_ip.protocol!=PROTOCOL_TCP&&packet_ip.protocol!=PROTOCOL_UDP){
			fseek(fp,packet_head.pcap_len-34,1);
			continue;	

		}
		
		ipheadlen=packet_ip.version_headlen&0x0F;
		if(ipheadlen==5){
			unread_tcp=packet_head.pcap_len-54;
			unread_udp=packet_head.pcap_len-42;
		}	
		else{
			ipheadlen=(ipheadlen-5)*4;
			unread_tcp=packet_head.pcap_len-54-ipheadlen;
			unread_udp=packet_head.pcap_len-42-ipheadlen;
			fseek(fp,ipheadlen,1);
		}

		
		switch(packet_ip.protocol){
		case PROTOCOL_TCP:{
			fread(&segment_tcp,sizeof(tcp_tag),1,fp);
			
			/*timedelay operation begin*/
			gettimedelay(&packet_head,&packet_ip,&segment_tcp,&unhandled,&handled,&syn_num,&syn_ack_num);
			/*timedelay operation end*/
			/*service op begin*/
			porttemp=changeseq_s(segment_tcp.des_port);
			portswap=changeseq_s(segment_tcp.src_port);
			if(porttemp<1024){
				int j=ClientIsIn(&pservice[porttemp].pclient,packet_ip.src_ip,segment_tcp.src_port);			 
                                //printf("Later i=%d  return=%d ip:%x port:%x\n",i,j,packet_ip.src_ip,segment_tcp.src_port);
                                if(j==1){
						pservice[porttemp].clientnum+=1;		
				}
		//		printf("%d server_port:%u\n",i,porttemp);
			//	printf("%d tcp s:%u  d:%u\n",i,segment_tcp.src_port,segment_tcp.des_port);			
			}
			if(portswap<1024){
				int k=ServerIsIn(&pservice[portswap].pserver,packet_ip.src_ip);
				if(k==1){
					pservice[portswap].servernum++;
				}

			}
			
			/*service op end*/		
			fseek(fp,unread_tcp,1);
       			break;	
		}
		case PROTOCOL_UDP:{
			fread(&datagrame_udp,sizeof(udp_tag),1,fp);
			/*service op begin*/
			porttemp=changeseq_s(datagrame_udp.des_port);
			portswap=changeseq_s(datagrame_udp.src_port);
			if(porttemp<1024){
				int j=ClientIsIn(&pservice[porttemp].udppclient,packet_ip.src_ip,datagrame_udp.src_port);			 
                                //printf("Later i=%d  return=%d ip:%x port:%x\n",i,j,packet_ip.src_ip,segment_tcp.src_port);
                                if(j==1){
						pservice[porttemp].udpclientnum+=1;		
				}
		//		printf("%d server_port:%u\n",i,porttemp);
			//	printf("%d tcp s:%u  d:%u\n",i,segment_tcp.src_port,segment_tcp.des_port);			
			}
			if(portswap<1024){
				int k=ServerIsIn(&pservice[portswap].udppserver,packet_ip.src_ip);
				if(k==1){
					pservice[portswap].udpservernum++;
				}

			}
			//	printf("%d udp s:%u  d:%u\n",i,datagrame_udp.src_port,datagrame_udp.des_port);			
			/*service op end*/
			fseek(fp,unread_udp,1);
			break;
		}

		default:
			printf("error!addert\n");
			break;

		}
		continue;
	}
	/*timdelay operation begin*/
	del_unhandled(unhandled);
	handled_merage(handled);
	*ptimedelay_head=handled;
       /*timedelay operarion end*/		
}
