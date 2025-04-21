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

struct file_resource_record
{
	unsigned char* host;
	long ttl;
	unsigned char* internet_type;
	unsigned char* resource_type;
	unsigned char* data;
};

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




int main(int argc, char *argv[])
{
    int sock;// socket num of TCP socket
    struct sockaddr_in echoServAddr;
    struct sockaddr_in echoClntAddr; // the IP address and portnum of server and client
    unsigned int cliAddrLen;
    unsigned char echoBuffer[65536]; // used to receive information
    unsigned short echoServPort;
    int recvMsgSize;
    
    echoServPort = atoi(argv[1]); //53
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock<0){
        printf("failed socket\n");
    }
    memset(&echoServAddr, 0, sizeof(echoServAddr)); // clear echoBuffer
	const char* local_server_IP = "127.0.0.5";
    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_addr.s_addr = inet_addr(local_server_IP);
    echoServAddr.sin_port = htons(echoServPort); // set the parameter of server address(self)
    if((bind(sock, (struct sockaddr*)&echoServAddr, sizeof(echoServAddr)))<0){
        printf("failed bind\n");
        exit(1);
    }


    for(;;){
		printf("listening to %d port\n",echoServPort); //TCP
    	if(listen(sock,100) == -1)
    	{
        	perror("listen");
        	exit(1);
    	}

		int echoClntLength = sizeof(echoClntAddr);
		printf("waiting for connecting\n");
    	int conn = accept(sock, (struct sockaddr*)&echoClntAddr, &echoClntLength); // accept connection
    	if(conn<0)
    	{
        	perror("connect");
        	exit(1);
    	}
		printf("connect success\n");


        cliAddrLen = sizeof(echoClntAddr);
        recvMsgSize = recv(conn, echoBuffer, 65536, 0); // TCP receive
        if(recvMsgSize<0){
            printf("failed recv\n");
            exit(1);
        }


		struct DNS_HEADER* client_header = (struct DNS_HEADER*)&echoBuffer[2]; // read the information received
		unsigned char* client_qname = (unsigned char*)&echoBuffer[2 + sizeof(struct DNS_HEADER)];
		int client_stop = 0;
		unsigned char* print_name = ReadName(client_qname, echoBuffer, &client_stop); // read the query name
		printf("The DNS client needs the IP address of %s\n", print_name);
		struct QUESTION* client_qinfo = (struct QUESTION*)&echoBuffer[2 + sizeof(struct DNS_HEADER) + strlen((const char*)client_qname) + 1];



		unsigned char buf[65536]; // buffer to transmit data to other server
    	unsigned char* qname;
    	unsigned char* host=print_name;
		unsigned char host_split_buf[40];
		unsigned char* host_split = (unsigned char*) &host_split_buf;
		strcpy(host_split, host); // used to store and spilt the domain name
    	struct DNS_HEADER *dns = NULL;
		struct QUESTION *qinfo = NULL;

    	dns = (struct DNS_HEADER *)&buf[2];

		dns->id = client_header->id;;
		dns->qr = 1; //response
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
		dns->ans_count = 0;
		dns->auth_count = htons(1);
		dns->add_count = htons(1);

    	qname =(unsigned char*)&buf[2 + sizeof(struct DNS_HEADER)];
    	unsigned char* ptr = qname;
    	ChangetoDnsNameFormat(qname , host); // convert the domain name to dns format
    	qinfo =(struct QUESTION*)&buf[2 + sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

		qinfo->qtype = client_qinfo->qtype; //A,MX,CNAME,NS
		qinfo->qclass = htons(1); //its internet

    	int stop = 0;
    	unsigned char* name = (unsigned char*)&buf[2 + sizeof(struct DNS_HEADER)];
    	unsigned char* string = ReadName(name, buf, &stop);

		unsigned char* find_spot = (unsigned char*) &host_split_buf; // used to match the .
		int host_length = 1;
		while(*find_spot != '\0')
		{
			if(*find_spot == '.')
			{
				host_length++;
			}
			find_spot++;
		}
		unsigned char* tail;// get the top level domain
		tail = strtok(host_split, ".");
		int host_split_count = 1;
		unsigned char* before_tail;
		do
		{
			tail = strtok(NULL, ".");
			if(host_split_count == host_length - 2)
			{
				before_tail = tail;
			}
			host_split_count++;
		}
		while(host_split_count < host_length);
		unsigned char server_or_host_buf[40];
		unsigned char* server_or_host = (unsigned char*)&server_or_host_buf;
		if(strcmp(tail, "cn") == 0 && strcmp(before_tail, "edu") == 0) // match the second level domain with server name
		{
			strcpy(server_or_host, "edu_server");
		}
		else if(strcmp(tail, "us") == 0 && strcmp(before_tail, "gov") == 0)
		{
			strcpy(server_or_host, "gov_server");
		}
		else
		{
			strcpy(server_or_host, "none");
		}

		// write the authority part
		unsigned char* authority_domain_name = (unsigned char*)&buf[2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION)];
		unsigned char* client_qname_duplicate;
		unsigned char duplicate_buf[40];
		memset(duplicate_buf,0,sizeof(duplicate_buf)); // duplicate the previous server_or_host string
		client_qname_duplicate = (unsigned char*)&duplicate_buf; // used to store the name of server
		strcpy(client_qname_duplicate, print_name);
		ChangetoDnsNameFormat(authority_domain_name, client_qname_duplicate);
		
		struct R_DATA* authority_header = (struct R_DATA*)&buf[2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) + strlen((const char*)authority_domain_name) + 1];
		authority_header->type = htons(2);//NS type
    	authority_header->_class = htons(1);
    	authority_header->ttl = htons(100);
    	authority_header->data_len = htons(0);

		unsigned char* server_or_host_duplicate;
		unsigned char duplicate_buf2[40];
		server_or_host_duplicate = (unsigned char*)&duplicate_buf2;
		strcpy(server_or_host_duplicate, server_or_host);
		unsigned char* server_or_host_ptr = (unsigned char*)&buf[2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) + strlen((const char*)authority_domain_name) + 1 + sizeof(struct R_DATA)];
		ChangetoDnsNameFormat(server_or_host_ptr, server_or_host_duplicate);

		authority_header->data_len = htons(strlen(server_or_host_ptr) + 1);

		int now_length =  2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) + 
		strlen((const char*)authority_domain_name) + 1 + sizeof(struct R_DATA) + strlen(server_or_host_ptr) + 1 ;

		//write additional RR
		unsigned char* domain_name = (unsigned char*)&buf[now_length];

    	ChangetoDnsNameFormat(domain_name, server_or_host);

    	struct R_DATA* answer_header = (struct R_DATA*)&buf[now_length + strlen((const char*)domain_name) + 1];
    	answer_header->type = htons(1);
    	answer_header->_class = htons(1);
    	answer_header->ttl = htons(100);
    	answer_header->data_len = htons(4);

    	unsigned char* answer = (unsigned char*)&buf[now_length + strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)];
	
		if(strcmp(before_tail, "edu") == 0 && strcmp(tail, "cn") == 0)
		{
			memset(answer, 127, 1); answer++;
			memset(answer, 0, 1); answer++;
    		memset(answer, 0, 1); answer++;
			memset(answer, 6, 1); answer++;
		}
		else if(strcmp(before_tail, "gov") == 0 && strcmp(tail, "us") == 0)
		{
			memset(answer, 127, 1); answer++;
			memset(answer, 0, 1); answer++;
    		memset(answer, 0, 1); answer++;
			memset(answer, 7, 1); answer++;
		}
		else
		{
			memset(answer, 0, 1); answer++;
			memset(answer, 0, 1); answer++;
    		memset(answer, 0, 1); answer++;
			memset(answer, 0, 1); answer++;
		}

		int length = now_length + strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)+ 4 + 1;

		unsigned char* head_length_ptr = (unsigned char*)&buf;
		memset(head_length_ptr, ((length - 2) - (length - 2) % 256)/256, 1);head_length_ptr++;
		memset(head_length_ptr, (length - 2) % 256, 1);

        printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin_addr));
        if((send(conn, (char*)buf, length, 0)) < 0)
        {
            printf("failed send\n");
        }

		close(conn);
    }
}