/***********************************
File name:getconfig.c
Author:Qingqing Liang
Function:the definition of the getConfigValue()
************************************/

#include "head.h"
#define SIZE_CONTAINER 100
/*******************************************
function:get the data of the config.ini
if success return 0 and failure return -1
szPath: the path of the config.ini
szRoot: the name of the configuration project
szAddress:the address of the database and match the address in the config.ini
szDb:the name of the database and match the database int the config.ini
szUser:the name of the user of the database and match the user in the config.ini
szPaddwd: the password of the user and match the password in the config.ini
******************************************/
int getConfigValue(char *szPath,char *szRoot,char *szAddress,char *szDb,char *szUser,char *szPasswd){
	FILE *fp;
	int nFlag=0;
	int aFlag=0,dFlag=0,uFlag=0,pFlag=0;
	char *pos;
	char buf[1024],szRootExt[100];
	fp=fopen(szPath,"r");
	if(fp==NULL){
		printf("cannot open the config file!\n");
		return -1;
	
	}
	sprintf(szRootExt,"[%s]",szRoot);
	int i=0;
	while(!feof(fp)){
		memset(buf,0,sizeof(buf));
		fgets(buf,sizeof(buf),fp);
		if(buf[0]=='#') continue;
		if(nFlag==0&&buf[0]!='[') continue;
		else if(nFlag==0&&buf[0]=='['){
			if(strncmp(buf,szRootExt,strlen(szRootExt))==0)
			nFlag=1;
		}
		else if(nFlag==1 && buf[0]=='['){
			break;
		}
		else{
			if(aFlag==0&&strncmp(buf,szAddress,strlen(szAddress))==0){
				aFlag=1;
				memset(szAddress,0,SIZE_CONTAINER);
				pos=strstr(buf,"=");
				strncpy(szAddress,pos+1,strlen(pos+1)-1);	
			}
			if(dFlag==0&&strncmp(buf,szDb,strlen(szDb))==0){
				dFlag=1;
				memset(szDb,0,SIZE_CONTAINER);
				pos=strstr(buf,"=");
				strncpy(szDb,pos+1,strlen(pos+1)-1);	
			}
			if(uFlag==0&&strncmp(buf,szUser,strlen(szUser))==0){
				uFlag=1;
				memset(szUser,0,SIZE_CONTAINER);
				pos=strstr(buf,"=");
				strncpy(szUser,pos+1,strlen(pos+1)-1);
			}	
			if(pFlag==0&&strncmp(buf,szPasswd,strlen(szPasswd))==0){
				pFlag=1;
				memset(szPasswd,0,SIZE_CONTAINER);
				pos=strstr(buf,"=");
				strncpy(szPasswd,pos+1,strlen(pos+1)-1);
			}	
		}


	}
	fclose(fp);
	if(aFlag==1&&uFlag==1&&pFlag==1)
		return 0;
	return -1;

}



