/***********************************************************
File Name:dboperation.c
Author:Zhipeng Wang && Qingqing Liang
Description: the database operation and will put the result of the 
	statistic of the into the database;
*****************************************************/
#include <mysql.h>
#include "head.h"
#define STRING_SIZE 50
#define DROP_TOTOALFLOW "DROP TABLE IF EXISTS t_totalflow"
#define DROP_IPTOIP "DROP TABLE IF EXISTS t_iptoip"
#define DROP_TIMEDELAY "DROP TABLE IF EXISTS t_timedelay"
#define DROP_SERVICE  "DROP TABLE IF EXISTS t_service"
#define DROP_TOPTOSCREEN    "DROP TABLE IF EXISTS t_iptoiptoscreen"
#define DROP_TIMEDELAYTOSCREEN "DROP TABLE IF EXISTS t_timedelaytopk"
#define DROP_TIMESTAMP "DROP TABLE IF EXISTS t_timestamp"
#define DROPCOMMIT "set autocommit=0"
#define COMMIT "COMMIT"
#define CREATE_TOTALFLOW "CREATE TABLE t_totalflow(time INT,packets INT,bytes INT)"
#define CREATE_IPTOIP "CREATE TABLE t_iptoip(scrip INT(32) UNSIGNED,descip INT(32) UNSIGNED,packets INT(32) unsigned ,bytes INT(32) unsigned);"
#define CREATE_TIMEDELAYTOSCREEN "CREATE TABLE t_timedelaytopk as select scrip as scrip,descip as descip,sec_s as delay_s,sec_c as delay_c from t_timedelay order by delay_s+delay_c desc limit 0,50;"
#define CREATE_TIMEDELAY "CREATE TABLE t_timedelay(scrip INT(32) UNSIGNED,descip INT(32) UNSIGNED,sec_s INT(32) UNSIGNED,sec_c INT(32) UNSIGNED)"
#define CREATE_SERVICE "CREATE TABLE t_service(port INT(32), num INT(32), type_cs INT(32), type_p INT(32));"
#define INSERT_TOTALFLOW "INSERT INTO t_totalflow(time,packets,bytes) VALUES(?,?,?)"
#define INSERT_IPTOIP "INSERT INTO t_iptoip(scrip,descip,packets,bytes) VALUES(?,?,?,?)"
#define INSERT_TIMEDELAY "INSERT INTO t_timedelay(scrip,descip,sec_s,sec_c) VALUES(?,?,?,?)"
#define INSERT_SERVICE  "INSERT INTO t_service(port,num,type_cs,type_p) VALUES(?,?,?,?)"
#define INSERT_TIMESTAMP  "INSERT INTO t_timestamp values(localtime);"
MYSQL_STMT    *stmt;
MYSQL_STMT    *stmt1;
MYSQL_STMT    *stmt2;
MYSQL_STMT    *stmt3;
MYSQL_BIND    bin[3];
MYSQL_BIND    bin1[4];
MYSQL_BIND    bin2[4];
MYSQL_BIND    bin3[4];
my_ulonglong  affected_rows;
uint_32       param_count;
uint_32       small_data;
uint_32       int_data;
uint_32       str_data;
uint_32       str_byte;
uint_32       t_sec_f;
uint_32       t_millsec_f;
uint_32       t_sec_s;
uint_32       t_millsec_s;
uint_32       t_port ;
uint_32	      t_num ;
uint_32       t_type_cs;
uint_32       t_type_p ;
my_bool       is_null;
my_bool       is_unsigned ;
void dboperation(FILE *fp,char *szAddress,char *szDb,char *szUser,char *szPasswd){      
        MYSQL *mysql = mysql_init(NULL);   
    if(!mysql_real_connect(mysql,szAddress,szUser,szPasswd,szDb,0, NULL, CLIENT_FOUND_ROWS))  
    {
        printf("Cannot conncet to the database\n");
        return;
    }
	else 
	{
		printf("connect to database successfully\n");
	 }  
	if (mysql_query(mysql, DROP_TOTOALFLOW))
	{	
  	fprintf(stderr, " DROP TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
        if (mysql_query(mysql, DROP_TIMEDELAYTOSCREEN))
	{	
  	fprintf(stderr, " DROP TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
	if (mysql_query(mysql, DROP_IPTOIP))
	{	
  	fprintf(stderr, " DROP TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
	if (mysql_query(mysql, DROP_TIMEDELAY))
	{	
  	fprintf(stderr, " DROP TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
	if (mysql_query(mysql, DROP_SERVICE))
	{	
  	fprintf(stderr, " DROP TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
 	if (mysql_query(mysql, DROPCOMMIT))
	{	
  	fprintf(stderr, " DROP commit failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
	}
	if (mysql_query(mysql, CREATE_TOTALFLOW))
	{
  	fprintf(stderr, " CREATE TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
        if (mysql_query(mysql, CREATE_IPTOIP))
	{
  	fprintf(stderr, " CREATE TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
	 if (mysql_query(mysql, CREATE_TIMEDELAY))
	{
  	fprintf(stderr, " CREATE TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
	if (mysql_query(mysql, CREATE_SERVICE))
	{
  	fprintf(stderr, " CREATE TABLE failed\n");
  	fprintf(stderr, " %s\n", mysql_error(mysql));
  	exit(0);
	}
 	

/*total_flow*/
	total_flow *total_flow_statistic;
	total_flow_statistic=(total_flow *)malloc(TOTAL_FLOW_SIZE);
	total_flow_statistic->sec=HEAD_FLAG;
	int seq=0;
	int tf_count=0;


	iptoip saveipflow[65536];
	iptoip *tempip;
	iptoip *tempswap;
	iptoip *flag=(iptoip*)malloc(sizeof(iptoip));
	int num=0;
	int i;

	timedelay *head;

	service ps[1024];
	memset(ps,0,sizeof(service)*1024);
	printf("Begin to analysis the pcap file\n");
	getFileInfo(fp,total_flow_statistic,&seq,saveipflow,65536,flag,&head,ps);
	printf("Finish analyzing the pcap file\n");
	
	printf("Begin to write the result to the database\n");
	total_flow *temp=total_flow_statistic->nextsec;
	total_flow *tempnext;
        stmt = mysql_stmt_init(mysql);
	if (!stmt)
	{
  	fprintf(stderr, " mysql_stmt_init(), out of memory\n");
  	exit(0);
	}
	if (mysql_stmt_prepare(stmt, INSERT_TOTALFLOW, strlen(INSERT_TOTALFLOW)))
	{
  	fprintf(stderr, " mysql_stmt_prepare(), INSERT failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
  	exit(0);
	}
	param_count= mysql_stmt_param_count(stmt);
	if (param_count != 3) /* validate parameter count */
	{
  	fprintf(stderr, " invalid parameter count returned by MySQL\n");
  	exit(0);
	}
        memset(bin, 0, sizeof(bin));
	bin[0].buffer_type= MYSQL_TYPE_LONG;
	bin[0].buffer= (char *)&int_data;
	bin[0].is_null= 0;
	bin[0].length= 0;

	bin[1].buffer_type= MYSQL_TYPE_LONG;
	bin[1].buffer= (char *)&small_data;
	bin[1].is_null= &is_null;
	bin[1].length= 0;

	bin[2].buffer_type= MYSQL_TYPE_LONG;
	bin[2].buffer= (char *)&str_data;
	bin[2].is_null= &is_null;
	bin[2].length= 0;
	if (mysql_stmt_bind_param(stmt, bin))
	{
  	fprintf(stderr, " mysql_stmt_bind_param() failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
  	exit(0);
	}
	while(temp!=NULL){
                int_data = temp->sec ;
 		small_data = temp->packets;
		str_data = temp->bytes;
                is_null= 0;
		tempnext=temp->nextsec;
		free(temp);
		temp=tempnext;              	
		if (mysql_stmt_execute(stmt))
			{
				fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
				fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
				exit(0);
				} 
	affected_rows= mysql_stmt_affected_rows(stmt);
	if (affected_rows != 1) /* validate affected rows */
	{
	fprintf(stderr, " invalid affected rows by MySQL\n");
		exit(0);
	}
}
	if (mysql_stmt_close(stmt))
	{
  	fprintf(stderr, " failed while closing the statement\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
  	exit(0);
	}
	free(total_flow_statistic);
	total_flow_statistic=NULL;

 	stmt1 = mysql_stmt_init(mysql);
	if (!stmt1)
	{
  	fprintf(stderr, " mysql_stmt_init(), out of memory\n");
  	exit(0);
	}
	if (mysql_stmt_prepare(stmt1, INSERT_IPTOIP, strlen(INSERT_IPTOIP)))
	{
  	fprintf(stderr, " mysql_stmt_prepare(), INSERT failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt1));
  	exit(0);
	}
	
	param_count= mysql_stmt_param_count(stmt1);

	if (param_count != 4) /* validate parameter count */
	{
  	fprintf(stderr, " invalid parameter count returned by MySQL\n");
  	exit(0);
	}
        memset(bin1, 0, sizeof(bin1));
	bin1[0].buffer_type= MYSQL_TYPE_LONG;
	bin1[0].buffer= (char *)&int_data;
	bin1[0].is_null= 0;
	bin1[0].length= 0;
        bin1[0].is_unsigned = 1 ;

	bin1[1].buffer_type= MYSQL_TYPE_LONG;
	bin1[1].buffer= (char *)&small_data;
	bin1[1].is_null= &is_null;
	bin1[1].length= 0;
        bin1[1].is_unsigned =1 ;

	bin1[2].buffer_type= MYSQL_TYPE_LONG;
	bin1[2].buffer= (char *)&str_data;
	bin1[2].is_null= &is_null;
	bin1[2].length= 0;
        
        bin1[3].buffer_type= MYSQL_TYPE_LONG;
	bin1[3].buffer= (char *)&str_byte;
	bin1[3].is_null= &is_null;
	bin1[3].length= 0; 
                
         
	if (mysql_stmt_bind_param(stmt1, bin1))
	{
  	fprintf(stderr, " mysql_stmt_bind_param() failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt1));
  	exit(0);
	}	
        for(i=0;i<65536;i++){
                  if(saveipflow[i].nextip!=NULL){    
                          ++num;
                        int_data =changeseq_l(saveipflow[i].src) ;
			small_data = changeseq_l(saveipflow[i].des) ;
                        str_data = saveipflow[i].packets ;
   			str_byte = saveipflow[i].bytes;
                     if (mysql_stmt_execute(stmt1))
			{
				fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
				fprintf(stderr, " %s\n", mysql_stmt_error(stmt1));
				exit(0);
				} 
			}
                          if(saveipflow[i].nextip!=flag){
                                  tempip=saveipflow[i].nextip;
                                  while(tempip!=NULL){
                                           int_data = changeseq_l(tempip->src) ;
					   small_data = changeseq_l(tempip->des );
                                           str_data = tempip->packets ;
   					   str_byte = tempip->bytes ;
 					    if (mysql_stmt_execute(stmt1))
					{
					fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
					fprintf(stderr, " %s\n", mysql_stmt_error(stmt1));
					exit(0);
					} 
                                          tempswap=tempip->nextip;
					  free(tempip);					  
                                          tempip=tempswap;
                                  }
                         }
                       }
          		
			if (mysql_stmt_close(stmt1))
			{
  			fprintf(stderr, " failed while closing the statement\n");
  			fprintf(stderr, " %s\n", mysql_stmt_error(stmt1));
  			exit(0);
			}      

        stmt2 = mysql_stmt_init(mysql);
	if (!stmt2)
	{
  	fprintf(stderr, " mysql_stmt_init(), out of memory\n");
  	exit(0);
	}
	if (mysql_stmt_prepare(stmt2, INSERT_TIMEDELAY, strlen(INSERT_TIMEDELAY)))
	{
  	fprintf(stderr, " mysql_stmt_prepare(), INSERT failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt2));
  	exit(0);
	}
	param_count= mysql_stmt_param_count(stmt2);
	if (param_count != 4) /* validate parameter count */
	{
  	fprintf(stderr, " invalid parameter count returned by MySQL\n");
  	exit(0);
	}
        memset(bin2, 0, sizeof(bin2));
	bin2[0].buffer_type= MYSQL_TYPE_LONG;
	bin2[0].buffer= (char *)&int_data;
	bin2[0].is_null= 0;
	bin2[0].length= 0;
        bin2[0].is_unsigned = 1 ;

	bin2[1].buffer_type= MYSQL_TYPE_LONG;
	bin2[1].buffer= (char *)&small_data;
	bin2[1].is_null= &is_null;
	bin2[1].length= 0;
        bin2[1].is_unsigned =1 ;

	bin2[2].buffer_type= MYSQL_TYPE_LONG;
	bin2[2].buffer= (char *)&t_sec_f;
	bin2[2].is_null= &is_null;
	bin2[2].length= 0;
        
        bin2[3].buffer_type= MYSQL_TYPE_LONG;
	bin2[3].buffer= (char *)&t_sec_s;
	bin2[3].is_null= &is_null;
	bin2[3].length= 0; 
 	
         
	if (mysql_stmt_bind_param(stmt2, bin2))
	{
  	fprintf(stderr, " mysql_stmt_bind_param() failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt1));
  	exit(0);
	}	
	
	timedelay *peersdelay=head;
	timedelay *tempdelay;
	while(peersdelay!=NULL){
                int_data = changeseq_l(peersdelay->add.src_ip) ;
		small_data = changeseq_l(peersdelay->add.des_ip);
		t_sec_f = peersdelay->sec_f*1000000+peersdelay->millsec_f;
		t_sec_s = peersdelay->sec_s*1000000+peersdelay->millsec_s ;
		tempdelay=peersdelay->nextDelay;
		free(peersdelay);
		peersdelay=tempdelay;
		if (mysql_stmt_execute(stmt2))
		{
		fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt2));
		exit(0);
		} 
	}
		if (mysql_stmt_close(stmt2))
		{
  		fprintf(stderr, " failed while closing the statement\n");
  		fprintf(stderr, " %s\n", mysql_stmt_error(stmt2));
  		exit(0);
		}    
/*network service*/
	stmt3 = mysql_stmt_init(mysql);
	if (!stmt3)
	{
  	fprintf(stderr, " mysql_stmt_init(), out of memory\n");
  	exit(0);
	}
	if (mysql_stmt_prepare(stmt3, INSERT_SERVICE, strlen(INSERT_SERVICE)))
	{
  	fprintf(stderr, " mysql_stmt_prepare(), INSERT failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
  	exit(0);
	}
	param_count= mysql_stmt_param_count(stmt3);
	if (param_count != 4) /* validate parameter count */
	{
  	fprintf(stderr, " invalid parameter count returned by MySQL\n");
  	exit(0);
	}
        memset(bin3, 0, sizeof(bin3));
	bin3[0].buffer_type= MYSQL_TYPE_LONG;
	bin3[0].buffer= (char *)&t_port;
	bin3[0].is_null= 0;
	bin3[0].length= 0;

	bin3[1].buffer_type= MYSQL_TYPE_LONG;
	bin3[1].buffer= (char *)&t_num;
	bin3[1].is_null= &is_null;
	bin3[1].length= 0;

	bin3[2].buffer_type= MYSQL_TYPE_LONG;
	bin3[2].buffer= (char *)&t_type_cs;
	bin3[2].is_null= &is_null;
	bin3[2].length= 0;
        
        bin3[3].buffer_type= MYSQL_TYPE_LONG;
	bin3[3].buffer= (char *)&t_type_p;
	bin3[3].is_null= &is_null;
	bin3[3].length= 0;                     
	if (mysql_stmt_bind_param(stmt3, bin3))
	{
  	fprintf(stderr, " mysql_stmt_bind_param() failed\n");
  	fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
  	exit(0);
	}	
	for(i=0;i<1024;i++){
		if(ps[i].clientnum>0){
		freeNode(&ps[i].pclient);
		freeNodeS(&ps[i].pserver);
		freeNode(&ps[i].udppclient);
		freeNodeS(&ps[i].udppserver);
		}
	}
	for(i=0;i<1024;i++){
		if(ps[i].clientnum>0){
			t_port = i ;
			t_num = ps[i].clientnum ;
 			t_type_cs = 1 ;
			t_type_p = 1;
			if (mysql_stmt_execute(stmt3))
			{
			fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
			fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
			exit(0);
			} 
		}
		if(ps[i].servernum>0){
			t_port = i ;
			t_num = ps[i].servernum ;
 			t_type_cs = 2 ;
			t_type_p = 1;
			if (mysql_stmt_execute(stmt3))
			{
			fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
			fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
			exit(0);
			} 
		}
		if(ps[i].udpclientnum>0){
			t_port = i ;
			t_num = ps[i].udpclientnum ;
 			t_type_cs = 1 ;
			t_type_p = 2;
			if (mysql_stmt_execute(stmt3))
			{
			fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
			fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
			exit(0);
			} 
		}
		if(ps[i].udpservernum>0){
			t_port = i ;
			t_num = ps[i].udpservernum ;
 			t_type_cs = 2 ;
			t_type_p = 2;
			if (mysql_stmt_execute(stmt3))
			{
			fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
			fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
			exit(0);
			} 
		}
	}
			if (mysql_stmt_close(stmt3))
			{
  			fprintf(stderr, " failed while closing the statement\n");
  			fprintf(stderr, " %s\n", mysql_stmt_error(stmt3));
  			exit(0);
			} 
		 	if (mysql_query(mysql, CREATE_TIMEDELAYTOSCREEN))
			{
  			fprintf(stderr, " CREATE TABLE failed\n");
  			fprintf(stderr, " %s\n", mysql_error(mysql));
  			exit(0);
			}
	fclose(fp);
        printf("OK!Has already put the result of flow analyzing to the database\n");

}
