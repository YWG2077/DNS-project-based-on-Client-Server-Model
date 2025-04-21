#include<stdio.h>	//printf
#include<string.h>	//strlen
#include<stdlib.h>	//malloc
#include<sys/socket.h>	
#include<arpa/inet.h>	//IP address, portnum, htons, ntohs...
#include<netinet/in.h>
#include<unistd.h>	//pid
#include<ctype.h>
#include<stdbool.h>


#define T_A 1 //IPv4 IP address
#define T_NS 2 //nameserver
#define T_CNAME 5 // canonical name
#define T_MX 15 //mail exchanger



struct DNS_HEADER
{
	unsigned short id; // ID

	unsigned char rd :1; // recursive query 
	unsigned char tc :1; // truncated
	unsigned char aa :1; // authoratative answer
	unsigned char opcode :4; 
	unsigned char qr :1; // query/response

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // reserved for future use
	unsigned char ra :1; // recursion available

	unsigned short q_count; // question entry number
	unsigned short ans_count; // answer entry number
	unsigned short auth_count; // authority entry number
	unsigned short add_count; // resource entry number
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype; // question type
	unsigned short qclass; // internet
};

//resource record structure
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type; // rr type 
	unsigned short _class; // internet
	unsigned int ttl; // time to live
	unsigned short data_len; // length of latter data
};
#pragma pack(pop)

//resource record
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

//Query
typedef struct
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

//convert www.google.com to 3www6google3com 

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;// lock is used to get the position of a .
	strcat((char*)host,"."); // add a . in the last position
	
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count) // read name from buffer and change it to www.google.com format
{
	unsigned char *name;
	unsigned int p=0;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256); // distribute buffer size

	name[0]='\0';

	//read dns format name
	while(*reader!=0)
	{
		name[p++]=*reader;
		reader = reader+1;
		*count = *count + 1;
	}

	name[p]='\0'; //complete the total string

	//convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++) 
	{
		p=name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
	return name;
}




int main(int argc, char *argv[]){
    int sock_tcp;
	int sock_udp; // define the udp and tcp socket num
    struct sockaddr_in echoServAddr;
    struct sockaddr_in echoClntAddr; // the IP address and portnum of server and client
    unsigned int cliAddrLen;
    unsigned char echoBuffer[65536]; // used to receive information
    unsigned short echoServPort;
    int recvMsgSize;
    
    echoServPort = atoi(argv[1]); // 53
    sock_tcp = socket(AF_INET, SOCK_STREAM, 0);
	sock_udp = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock_tcp<0 || sock_udp<0){
        printf("failed socket\n");
    }
    memset(&echoServAddr, 0, sizeof(echoServAddr)); // clear echoBuffer
	const char* local_server_IP = "127.0.0.2";
    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_addr.s_addr = inet_addr(local_server_IP);
    echoServAddr.sin_port = htons(echoServPort); // set the parameter of server address(self)
    if((bind(sock_udp, (struct sockaddr*)&echoServAddr, sizeof(echoServAddr)))<0){
        printf("failed to bind with %s\n", local_server_IP);
        exit(1);
    }

	bool firstquery = true; // receive the client query, sent packet to root server
	int iteration = 1;
	unsigned char query_question_buf[100];
	unsigned char* query_question = (unsigned char*)&query_question_buf;
	unsigned short query_type;
    unsigned char buf[65536]; // used to send packet
	short client_port_num; // used to store the portnum of client


    for(;;){

		if(firstquery) // first step of iterative query
		{
			cliAddrLen = sizeof(echoClntAddr);
			memset(echoBuffer, 0, sizeof(echoBuffer));
    		recvMsgSize = recvfrom(sock_udp, echoBuffer, 65536, 0, (struct sockaddr*)&echoClntAddr, &cliAddrLen);
    		if(recvMsgSize<0){
        		printf("failed recv from client.\n");
        		exit(1);
    		}

			close(sock_udp);
			

    		client_port_num = ntohs(echoClntAddr.sin_port); // get the portnum of client
			printf("The IP address of client is %s, port number is %hd\n\n",inet_ntoa(echoClntAddr.sin_addr), client_port_num);
    		struct DNS_HEADER* client_header = (struct DNS_HEADER*)&echoBuffer; // read the information of query header
			unsigned char* client_qname = (unsigned char*)&echoBuffer[sizeof(struct DNS_HEADER)];
			int client_stop = 0;
			unsigned char* print_name = ReadName(client_qname, echoBuffer, &client_stop); // read the domain name in question
			strcpy(query_question, print_name);
			printf("The DNS client needs the information of %s\n\n", print_name);
			struct QUESTION* client_qinfo = (struct QUESTION*)&echoBuffer[sizeof(struct DNS_HEADER) + strlen((const char*)client_qname) + 1];
			printf("The local server has resoluted the client packet.\n\n");
			query_type = ntohs(client_qinfo->qtype);

    		unsigned char* qname;
    		unsigned char* host=print_name;
    		struct DNS_HEADER *dns = NULL;
			struct QUESTION *qinfo = NULL;

    		dns = (struct DNS_HEADER *)&buf[2]; // reserve 2 bits for TCP packet length

			dns->id = client_header->id;;
			dns->qr = 0; //query
			dns->opcode = 0; //standard query
			dns->aa = 0; //not authoritative
			dns->tc = 0; //not truncated
			dns->rd = 0; 
			dns->ra = 0; 
			dns->z = 0;
			dns->ad = 0;
			dns->cd = 0;
			dns->rcode = 0;
			dns->q_count = htons(1); //only 1 question
			dns->ans_count = htons(0);
			dns->auth_count = 0;
			dns->add_count = 0;

    		qname =(unsigned char*)&buf[2 + sizeof(struct DNS_HEADER)];
    		ChangetoDnsNameFormat(qname , host); // write the domain name 
			printf("The local server will ask the root server information about %s\n\n", host);
    		qinfo =(struct QUESTION*)&buf[2 + sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

			qinfo->qtype = client_qinfo->qtype; //A,MX,CNAME,NS
			qinfo->qclass = htons(1); //internet

			int length = 2 + sizeof(struct DNS_HEADER) + strlen((const char*) qname) + 1 + sizeof(struct QUESTION);
    		echoClntAddr.sin_family = AF_INET;
    		unsigned char* root_server_IP = "127.0.0.3"; // IP address of rootServer
    		echoClntAddr.sin_addr.s_addr = inet_addr(root_server_IP);
    		echoClntAddr.sin_port = htons(53);

			unsigned char* head_length_ptr = (unsigned char*)&buf; // set the TCP packet length in the 2 bits of the header
			memset(head_length_ptr, ((length - 2) - (length - 2) % 256)/256, 1);head_length_ptr++;
			memset(head_length_ptr, (length - 2) % 256, 1); // the length doesn't contain the 2 bits itself

			sock_tcp = socket(AF_INET, SOCK_STREAM, 0); // establish TCP connection with different servers

			if((bind(sock_tcp, (struct sockaddr*)&echoServAddr, sizeof(echoServAddr)))<0){
        		printf("failed to bind with %s\n", local_server_IP);
        		exit(1);
    		}
			
    		
    		if (connect(sock_tcp, (struct sockaddr *)&echoClntAddr, sizeof(echoClntAddr)) < 0)
   			{
        		perror("connect error\n");
        		exit(1);
    		}

    		if((send(sock_tcp, (char*)buf, length, 0)) < 0)
    		{
    		    printf("failed send to root server.\n");
    		}

			firstquery = false;
		}
		else
		{
			cliAddrLen = sizeof(echoClntAddr); // receive the information
			memset(echoBuffer, 0, sizeof(echoBuffer));
        	recvMsgSize = recv(sock_tcp, echoBuffer, 65536, 0);
        	if(recvMsgSize<0){
        	    printf("failed recv\n");
	            exit(1);
 	       	}


			bool finalquery = false; // if get the authoratative answer, it is true.
			struct DNS_HEADER* client_header = (struct DNS_HEADER*)&echoBuffer[2];
			if(client_header->ans_count >= htons(1)){ // have authoratative answer
				finalquery = true;
			}

    	    if(finalquery)
        	{
				close(sock_tcp);
				printf("Iteration %d: received information from %s.\n",iteration, inet_ntoa(echoClntAddr.sin_addr));
        	    printf("Iteration %d: Send the authoratative answer to client.\n\n",iteration);
        	    unsigned char* clientip = "127.0.0.1"; // send packet back to client
        	    echoClntAddr.sin_addr.s_addr = inet_addr(clientip);
        	    echoClntAddr.sin_family = AF_INET;
        	    echoClntAddr.sin_port = htons(client_port_num);

				sock_udp = socket(PF_INET, SOCK_DGRAM, 0); // establish UDP communication

				if((bind(sock_udp, (struct sockaddr*)&echoServAddr, sizeof(echoServAddr)))<0){
       				printf("failed bind\n");
        			exit(1);
    			}

				unsigned char* sendbuf = (unsigned char*)&echoBuffer;
				sendbuf = sendbuf + 2; // abandon the first two TCP bits

        	    if((sendto(sock_udp, (char*)sendbuf, recvMsgSize - 2, 0, (struct sockaddr*)&echoClntAddr, sizeof(echoClntAddr))) < 0)
        	    {
        	        printf("failed send to the client.\n");
        	    }
				firstquery = true; // reset parameters
				finalquery = false;
				iteration = 0;
        	}
        	else
        	{
				close(sock_tcp);

				unsigned char* client_qname = (unsigned char*)&echoBuffer[2 + sizeof(struct DNS_HEADER)]; // read the information received
				int client_stop = 0;
				unsigned char* print_name = ReadName(client_qname, echoBuffer, &client_stop); // get the name of query
				struct QUESTION* client_qinfo = (struct QUESTION*)&echoBuffer[2 + sizeof(struct DNS_HEADER) + strlen((const char*)client_qname) + 1];
				unsigned char* echoServerReader = (unsigned char*)&echoBuffer[2 + sizeof(struct DNS_HEADER) + strlen((const char*)client_qname) + 1 + sizeof(struct QUESTION)];
				int stop = 0;

				struct RES_RECORD authority; // read the authoritative nameserver section
				authority.name = ReadName(echoServerReader, echoBuffer, &stop);
        
				echoServerReader = echoServerReader + stop;
				authority.resource = (struct R_DATA*)echoServerReader;
				echoServerReader = echoServerReader + sizeof(struct R_DATA);
				echoServerReader = echoServerReader + ntohs(authority.resource->data_len);

				stop = 0; // read the addition section
				struct RES_RECORD addition;
				addition.name = ReadName(echoServerReader, echoBuffer, &stop);
        
				echoServerReader = echoServerReader + stop;
				addition.resource = (struct R_DATA*)echoServerReader;
				echoServerReader = echoServerReader + sizeof(struct R_DATA);
				addition.rdata = (unsigned char*)malloc(ntohs(addition.resource->data_len));
				int j = 0;
				bool false_domain = false;
				int count_0 = 0;
				while(j<ntohs(addition.resource->data_len)){
					addition.rdata[j] = echoServerReader[j];
					if(ntohs(addition.rdata[j]) == 0)
					{
						count_0++;
					}
					j++;
				}
				if(count_0 == 4)
				{
					
					printf("Detect domain name error, send the packet to client directly.\n\n");
					unsigned char* clientip = "127.0.0.1"; // send packet back to client
					echoClntAddr.sin_addr.s_addr = inet_addr(clientip);
					echoClntAddr.sin_family = AF_INET;
					echoClntAddr.sin_port = htons(client_port_num);

					sock_udp = socket(PF_INET, SOCK_DGRAM, 0); // establish UDP communication

					if((bind(sock_udp, (struct sockaddr*)&echoServAddr, sizeof(echoServAddr)))<0){
						printf("failed bind\n");
						exit(1);
					}

					unsigned char* sendbuf = (unsigned char*)&echoBuffer;
					sendbuf = sendbuf + 2; // abandon the first two TCP bits

					if((sendto(sock_udp, (char*)sendbuf, recvMsgSize - 2, 0, (struct sockaddr*)&echoClntAddr, sizeof(echoClntAddr))) < 0)
					{
						printf("failed send to the client.\n");
					}
					firstquery = true; // reset parameters
					finalquery = false;
					iteration = 0;
					continue;
				}
				addition.rdata[ntohs(addition.resource->data_len)] = '\0';

				memset(&buf, 0, sizeof(buf));
				unsigned char* qname;
				unsigned char* host=print_name;
				struct DNS_HEADER *dns = NULL;
				struct QUESTION *qinfo = NULL;

        	    dns = (struct DNS_HEADER *)&buf[2];

			    dns->id = client_header->id;;
			    dns->qr = 0; //query
			    dns->opcode = 0; //standard query
			    dns->aa = 0; //not authoritative
			    dns->tc = 0; //not truncated
			    dns->rd = 0; 
			    dns->ra = 0;
			    dns->z = 0;
			    dns->ad = 0;
			    dns->cd = 0;
			    dns->rcode = 0;
			    dns->q_count = htons(1); //only 1 question
        	    dns->ans_count = htons(0);
			    dns->auth_count = 0;
			    dns->add_count = 0;

        	    qname =(unsigned char*)&buf[2 + sizeof(struct DNS_HEADER)];
        	    ChangetoDnsNameFormat(qname , host);// change the query name to dns format and put it into the buffer
    		    qinfo =(struct QUESTION*)&buf[2 + sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 

			    qinfo->qtype = htons(query_type); //A,MX,CNAME,NS
			    qinfo->qclass = htons(1); //internet

        	    int length = 2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION);


        	    printf("Iteration %d: response to server %s\n", iteration, inet_ntoa(echoClntAddr.sin_addr)); // iteration 
				unsigned char nextip_buf[40];
        	    unsigned char* nextip = (unsigned char*)&nextip_buf;
				printf("Iteration %d: now we will send packet to server ", iteration);
        	    sprintf(nextip, "%hd.%hd.%hd.%hd", addition.rdata[0], addition.rdata[1], addition.rdata[2], addition.rdata[3]);
				puts(nextip); // read the information of next server IP address and convert it to correct format
        	    echoClntAddr.sin_addr.s_addr = inet_addr(nextip);
        	    echoClntAddr.sin_family = AF_INET;
        	    echoClntAddr.sin_port = htons(53);

				unsigned char* head_length_ptr = (unsigned char*)&buf; // input the length of TCP packet
				memset(head_length_ptr, ((length - 2) - (length - 2) % 256)/256, 1);head_length_ptr++;
				memset(head_length_ptr, (length - 2) % 256, 1);

				echoServAddr.sin_family = AF_INET;
    			echoServAddr.sin_addr.s_addr = inet_addr(local_server_IP);
    			echoServAddr.sin_port = htons(echoServPort);
				
				sock_tcp = socket(AF_INET, SOCK_STREAM, 0);

				if((bind(sock_tcp, (struct sockaddr*)&echoServAddr, sizeof(echoServAddr)))<0){
       				printf("failed bind\n");
       				exit(1);
    			}

				if (connect(sock_tcp, (struct sockaddr *)&echoClntAddr, sizeof(echoClntAddr)) < 0)
  				{
        			perror("connect");
        			exit(1);
    			}

        	    if((send(sock_tcp, (char*)buf, length, 0)) < 0)
        	    {
        	        printf("failed send to another server.\n");
        	    }
        	}
			iteration++;

		}

    }
}