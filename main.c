#include"head.h"
#define BUFFER_MAX_LEN 100
#define PCAPNAME "network.cap"
int main(int argc,char **argv){
    	char pathofpcap[BUFFER_MAX_LEN]=PCAPNAME;
    	if(argc==2){
		memset(pathofpcap,0,BUFFER_MAX_LEN);
		strcpy(pathofpcap,argv[1]);
    	}
    	FILE *fp;
        fp=fopen(pathofpcap,"rb");  
    	if(fp==NULL){
		printf("Has no such pcap file\n");
		exit(1);
	}
    	char root[BUFFER_MAX_LEN]="database";
    	char address[BUFFER_MAX_LEN]="address";
    	char database[BUFFER_MAX_LEN]="database";
    	char user[BUFFER_MAX_LEN]="user";
    	char passwd[BUFFER_MAX_LEN]="password";
    	char path[BUFFER_MAX_LEN]="config.ini";
    	if(getConfigValue(path,root,address,database,user,passwd)==-1){
		printf("Get the configuration information error\n");
		exit(1);
    	}
	dboperation(fp,address,database,user,passwd);
    	return 0;
}
