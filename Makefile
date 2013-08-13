pcap: getconfig.o pcapanalysis.o dboperation.o main.o
	gcc -o pcap getconfig.o pcapanalysis.o dboperation.o main.o -lmysqlclient 
getconfig.o: head.h getconfig.c
	gcc -c getconfig.c
pcapanalysis.o: head.h pcapanalysis.c
	gcc -c pcapanalysis.c
dboperation.o: head.h dboperation.c 
	gcc -c -I./include dboperation.c
main.o: head.h main.c
	gcc -c main.c
clean:
	rm getconfig.o pcapanalysis.o dboperation.o main.o
cleanAll:
	rm getconfig.o pcapanalysis.o dboperation.o main.o pcap
	
