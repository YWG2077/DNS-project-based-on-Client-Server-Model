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


int main(int argc, char *argv[]){

	FILE* fp = fopen("com_and_org_rr.txt", "r"); // open the file and read the information
    unsigned char read_file[1000];
    memset(read_file,0,sizeof(read_file));
    
	unsigned char anotherbuf[1000];
    unsigned char* first_line = anotherbuf;
    int lines = 0; // read the line number of file
    while(!feof(fp))
	{
		if (fgets(first_line, 128, fp) != NULL) 
		{
        	lines++;
    	}	  
	}
	fclose(fp);
	
   	FILE* afp = fopen("com_and_org_rr.txt", "r");
   	
   	struct file_resource_record myrecord[lines];
   	int i = 0;
   	
   	unsigned char file_buf[5000];
   	unsigned char* file_ptr = file_buf;
   	for(i = 0; i < lines; i++) // read each line and store them in the data structure
   	{
   		memset(read_file, 0, sizeof(read_file));
   		unsigned char* str = read_file;
   		fgets(str, 255, afp);
   		unsigned char* token;
   		token = strtok(str, " ");
   		int j = 0;
   		while(token != NULL)
   		{
   			if(j == 0)
   			{
   				myrecord[i].host = file_ptr;
   				strcpy(myrecord[i].host, token);
   				file_ptr = file_ptr + strlen((const char*)myrecord[i].host) + 1;
			}
			else if(j == 1)
			{
				myrecord[i].ttl = strtol(token, NULL, 10);
			}
			else if(j == 2)
			{
				myrecord[i].internet_type = file_ptr;
				strcpy(myrecord[i].internet_type, token);
				file_ptr = file_ptr + strlen((const char*)myrecord[i].internet_type) + 1;
			}
			else if(j == 3)
			{
				myrecord[i].resource_type = file_ptr;
				strcpy(myrecord[i].resource_type, token);
				file_ptr = file_ptr + strlen((const char*)myrecord[i].resource_type) + 1;
			}
			else if(j == 4)
			{
				myrecord[i].data = file_ptr;
				strcpy(myrecord[i].data, token);
				file_ptr = file_ptr + strlen((const char*)myrecord[i].data) + 1;
			}
   	 		token = strtok(NULL, " ");
   	 		j++;
   		}
    }
    fclose(afp);



    int sock; // socket num of TCP socket
    struct sockaddr_in echoServAddr;
    struct sockaddr_in echoClntAddr; // the IP address and portnum of server and client
    unsigned int cliAddrLen;
    unsigned char echoBuffer[65536]; // used to receive information
    unsigned short echoServPort;
    int recvMsgSize;
    
    echoServPort = atoi(argv[1]);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if(sock<0){
        printf("failed socket\n");
    }
    memset(&echoServAddr, 0, sizeof(echoServAddr));
	const char* local_server_IP = "127.0.0.4";
    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_addr.s_addr = inet_addr(local_server_IP);
    echoServAddr.sin_port = htons(echoServPort);
    if((bind(sock, (struct sockaddr*)&echoServAddr, sizeof(echoServAddr)))<0){
        printf("failed bind\n");
        exit(1);
    }

    for(;;){		
		printf("listening to %d port\n",echoServPort);
    	if(listen(sock,100) == -1)
    	{
        	perror("listen");
        	exit(1);
    	}

		int echoClntLength = sizeof(echoClntAddr);
		printf("waiting for connecting\n");
    	///成功返回非负描述字，出错返回-1
    	int conn = accept(sock, (struct sockaddr*)&echoClntAddr, &echoClntLength);
    	if(conn<0)
    	{
        	perror("connect");
        	exit(1);
    	}
		printf("connect success\n");

        cliAddrLen = sizeof(echoClntAddr);
		memset(echoBuffer,0,sizeof(echoBuffer));
        recvMsgSize = recv(conn, echoBuffer, 65536, 0);
        if(recvMsgSize<0){
            printf("failed recv\n");
            exit(1);
        }

		struct DNS_HEADER* client_header = (struct DNS_HEADER*)&echoBuffer[2];
		unsigned char* client_qname = (unsigned char*)&echoBuffer[2 + sizeof(struct DNS_HEADER)];
		int client_stop = 0;
		unsigned char* print_name = ReadName(client_qname, echoBuffer, &client_stop);
		printf("The DNS client needs the IP address of %s\n", print_name);
		struct QUESTION* client_qinfo = (struct QUESTION*)&echoBuffer[2 + sizeof(struct DNS_HEADER) + strlen((const char*)client_qname) + 1];		

		unsigned char buf[65536];
    	unsigned char* qname;
    	unsigned char* host=print_name;
    	struct DNS_HEADER *dns = NULL;
		struct QUESTION *qinfo = NULL;


		memset(buf,0,sizeof(buf));
    	dns = (struct DNS_HEADER *)&buf[2];

		dns->id = client_header->id;;
		dns->qr = 1; //This is a response
		dns->opcode = 0; //This is a standard query
		dns->aa = 1; //Not Authoritative
		dns->tc = 0; //This message is not truncated
		dns->rd = 0; //Recursion Desired
		dns->ra = 0; //Recursion not available! hey we dont have it (lol)
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1); //we have only 1 question
		dns->ans_count = htons(1);
		dns->auth_count = 0;
		dns->add_count = 0;

    	qname =(unsigned char*)&buf[2 + sizeof(struct DNS_HEADER)];
    	unsigned char* ptr = qname;
    	ChangetoDnsNameFormat(qname , host);
    	qinfo =(struct QUESTION*)&buf[2 + sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

		qinfo->qtype = client_qinfo->qtype; //type of the query , A , MX , CNAME , NS etc
		qinfo->qclass = htons(1); //its internet (lol)

    	int stop = 0;
    	unsigned char* name = (unsigned char*)&buf[2 + sizeof(struct DNS_HEADER)];
    	unsigned char* string = ReadName(name, buf, &stop);

    	unsigned char* domain_name = (unsigned char*)&buf[2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION)];
    	ChangetoDnsNameFormat(domain_name, host);

    	struct R_DATA* answer_header = (struct R_DATA*)&buf[2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) + strlen((const char*)domain_name) + 1];
    	answer_header->type = client_qinfo->qtype;
    	answer_header->_class = htons(1);
    	answer_header->ttl = htons(100);
    	answer_header->data_len = htons(4);

    	unsigned char* answer = (unsigned char*)&buf[2+ sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) 
                            + strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)];
		unsigned char* answer_ptr = answer;


		int i = 0;
		int j = 0;
		int ipv4_address[4] = {0,0,0,0};
		int length;


		if(ntohs(client_qinfo->qtype) == 1){
			while(i < lines)
			{
				if(strcmp(myrecord[i].host, string) == 0 && strcmp(myrecord[i].resource_type, "A") == 0)
				{
					unsigned char* token;
					printf("%s\n",myrecord[i].data);
					unsigned char* store_data;
					unsigned char store_data_buf[100];
					store_data = (unsigned char*)&store_data_buf;
					strcpy(store_data, myrecord[i].data);
    				token = strtok(store_data, ".");
    				do
    				{
    					int num = atoi(token);
						ipv4_address[j] = num; j++;
						printf("IP address:%d\n",num);
    					token = strtok(NULL, ".");
					}
					while(token != NULL);
				}
				i++;
			}
			
			memset(answer, ipv4_address[0], 1); answer++;
			memset(answer, ipv4_address[1], 1); answer++;
    		memset(answer, ipv4_address[2], 1); answer++;
			memset(answer, ipv4_address[3], 1); answer++;
			length = 2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) 
        			+ strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)+ 4 + 1;
		}
		else if(ntohs(client_qinfo->qtype) == 5 ){
			bool isfound = false;
			while(i < lines)
			{
				if(strcmp(myrecord[i].host, string) == 0 && strcmp(myrecord[i].resource_type, "CNAME") == 0)
				{
					unsigned char newbuf[30];
					unsigned char* cname_host = (unsigned char*)&newbuf;
					printf("%s\n",myrecord[i].data);
					strcpy(cname_host, myrecord[i].data);
					unsigned char* cname_host_ptr = (unsigned char*)&newbuf;
					int cname_host_length = strlen((const char*)cname_host);
					int k = 0;
					while(k < cname_host_length)
					{
						if((*cname_host_ptr == '\r') || (*cname_host_ptr == '\n'))
						{
							memset(cname_host_ptr, 0, 1);
						}
						k++; cname_host_ptr++;
					}
   					ChangetoDnsNameFormat(answer,cname_host);
					answer_header->data_len = htons(strlen((const char*)answer_ptr));
					isfound = true;
				}
				i++;
			}
			if(!isfound)
			{
				unsigned char* not_found;
				unsigned char not_found_buf[30];
				not_found = (unsigned char*)&not_found_buf;
				strcpy(not_found,"not found");
				ChangetoDnsNameFormat(answer, not_found);
				answer_header->data_len = htons(strlen((const char*)answer_ptr));
			}
			length = 2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) 
        			+ strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)+ strlen((const char*)answer_ptr) + 1;
		}
		else if(ntohs(client_qinfo->qtype) == 15 ){
			unsigned short* preference = (unsigned short*)&buf[2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) + strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)];
			*preference = htons(30);
			answer++; answer++;
			answer_ptr++; answer_ptr++;
			unsigned char newbuf[30];
			unsigned char* mail_host = (unsigned char*)&newbuf;
			bool isfound = false;
			while(i < lines)
			{
				if(strcmp(myrecord[i].host, string) == 0 && strcmp(myrecord[i].resource_type, "MX") == 0)
				{
					printf("%s\n",myrecord[i].data);
					strcpy(mail_host, myrecord[i].data);
					unsigned char* mail_host_ptr = (unsigned char*)&newbuf;
					int mail_host_length = strlen((const char*)mail_host);
					int k = 0;
					while(k < mail_host_length)
					{
						if((*mail_host_ptr == '\r') || (*mail_host_ptr == '\n'))
						{
							memset(mail_host_ptr, 0, 1);
						}
						k++; mail_host_ptr++;
					}
   					ChangetoDnsNameFormat(answer,mail_host);
					answer_header->data_len = htons(strlen((const char*)answer_ptr) + 3);
					isfound = true;
				}
				i++;
			}
			if(isfound)
			{
				length = 2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) 
        			+ strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)+ 2 + strlen((const char*)answer_ptr) + 1;
			
				unsigned char* new_ptr = answer_ptr + strlen((const char*)answer_ptr) + 1;
				ChangetoDnsNameFormat(new_ptr,mail_host);
				unsigned char* new_ptr2 = answer_ptr + strlen((const char*)answer_ptr) + 1;
				int k = 0;
				unsigned char* string2 = ReadName(new_ptr2,buf,&k);
		
				struct R_DATA* answer_header2 = (struct R_DATA*)&buf[length + strlen((const char*)new_ptr) + 1];
				answer_header2->type = htons(T_A);
				answer_header2->_class = htons(1);
				answer_header2->ttl = htons(100);
    			answer_header2->data_len = htons(4);

				unsigned char* answer2 = (unsigned char*)&buf[length + strlen((const char*)new_ptr) + 1 + sizeof(struct R_DATA)];
				i = 0;
				j = 0;
				while(i < lines){
					if(strcmp(myrecord[i].host, string2) == 0 && strcmp(myrecord[i].resource_type, "A") == 0){
						unsigned char* token;
						printf("%s\n",myrecord[i].data);
						unsigned char* store_data;
						unsigned char store_data_buf[100];
						store_data = (unsigned char*)&store_data_buf;
						strcpy(store_data, myrecord[i].data);
    					token = strtok(store_data, ".");
    					do
    					{
    						int num = atoi(token);
							ipv4_address[j] = num; j++;
    						token = strtok(NULL, ".");
						}
						while(token != NULL);
						break;
					}
					i++;
				}
				memset(answer2, ipv4_address[0], 1); answer2++;
				memset(answer2, ipv4_address[1], 1); answer2++;
    			memset(answer2, ipv4_address[2], 1); answer2++;
				memset(answer2, ipv4_address[3], 1); answer2++;

				length = length + strlen((const char*) new_ptr) + 1 + sizeof(struct R_DATA) + 4;
				dns->add_count = htons(1);
			}
			else
			{
				unsigned char* not_found;
				unsigned char not_found_buf[30];
				not_found = (unsigned char*)&not_found_buf;
				strcpy(not_found,"not found");
				ChangetoDnsNameFormat(answer, not_found);
				answer_header->data_len = htons(strlen((const char*)answer_ptr));
				length = 2 + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + sizeof(struct QUESTION) 
        			+ strlen((const char*)domain_name) + 1 +sizeof(struct R_DATA)+ 2 + strlen((const char*)answer_ptr) + 1;
			}

		}

		unsigned char* head_length_ptr = (unsigned char*)&buf;
		memset(head_length_ptr, ((length - 2) - (length - 2) % 256)/256, 1);head_length_ptr++;
		memset(head_length_ptr, (length - 2) % 256, 1);


        printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin_addr));
        if((send(conn, (char*)buf, length, 0)) < 0)
        {
            printf("failed send\n");
        }
		memset(echoBuffer, 0, sizeof(echoBuffer));
		memset(buf, 0, sizeof(buf));
		close(conn);
    }
}