#include<stdio.h>	
#include<string.h>	//string manipulation
#include<stdlib.h>	//malloc
#include<sys/socket.h>	//socket programming
#include<arpa/inet.h>	//IP address, portnum, htons, ntohs...
#include<netinet/in.h>
#include<unistd.h>	//pid


#define T_A 1 //IPv4 IP address
#define T_NS 2 //nameserver
#define T_CNAME 5 // canonical name
#define T_MX 15 //mail exchanger


void ngethostbyname (unsigned char* , int, unsigned char*, unsigned char*); //query the information with different types
void ChangetoDnsNameFormat (unsigned char*,unsigned char*); //change from www.google.com to DNS format
unsigned char* ReadName (unsigned char*,unsigned char*,int*);//read the domain name from buffer and change it from DNS format to www.google.com format

//DNS header
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

int main( int argc , char *argv[])
{
    unsigned char* type = argv[1]; // get the query type
	unsigned char* hostname = argv[2]; // get the host name want to query
	unsigned char ip_buf[20];
	unsigned char* IP_address;
	IP_address = (unsigned char*)&ip_buf;
	strcpy(IP_address, "127.0.0.2"); // IP address of local server
	unsigned char portnum_buf[20];
    unsigned char* portnum;
	portnum = (unsigned char*)&portnum_buf;
	strcpy(portnum, "53"); // port number of local server
	int type_num;
	if(strcmp(type,"A") == 0){ // three type of query
		type_num = T_A;
	}else if(strcmp(type,"CNAME") == 0){
		type_num = T_CNAME;
	}else if(strcmp(type,"MX") == 0){
		type_num = T_MX;
	}
	//query
	ngethostbyname(hostname , type_num, IP_address, portnum);

	return 0;
}

// DNS query, send a packet to localServer
void ngethostbyname(unsigned char *host , int query_type, unsigned char* IP_address, unsigned char* portnum)
{
	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s;

	struct sockaddr_in a;

	struct RES_RECORD answers[20],auth[20],addit[20]; //store the reply from server
	struct sockaddr_in dest;// IP address and portnum of destonation

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	printf("Resolving %s" , host);

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP interaction for client and localServer

	dest.sin_family = AF_INET;
	dest.sin_port = htons(atoi(portnum));
	dest.sin_addr.s_addr = inet_addr(IP_address); //dns server information

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //query
	dns->opcode = 0; //standard query
	dns->aa = 0; //not Authoritative
	dns->tc = 0; //not truncated
	dns->rd = 0; 
	dns->ra = 0; 
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname , host);// change the query name to dns format and put it into the buffer
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //query information

	qinfo->qtype = htons( query_type ); //A,MX,CNAME
	qinfo->qclass = htons(1); //internet

	printf("\nSending Packet...");
	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("sendto failed");
	}
	printf("Done");
	
	//Receive the answer
	i = sizeof dest;
	printf("\nReceiving answer...");
	if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
	}
	printf("Done");

	dns = (struct DNS_HEADER*) buf;

	//move ahead of the dns header
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	printf("\nThe response contains : "); // response information
	printf("\n %d Questions.",ntohs(dns->q_count));
	printf("\n %d Answers.",ntohs(dns->ans_count));
	printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
	printf("\n %d Additional records.\n\n",ntohs(dns->add_count));

	//read answers
	stop=0;


	for(i=0;i<ntohs(dns->ans_count);i++)
	{
		answers[i].name=ReadName(reader,buf,&stop); // read the answer name
		reader = reader + stop;
		printf("%s\n", answers[i].name);

		answers[i].resource = (struct R_DATA*)(reader);
		printf("type: %hd\n",ntohs(answers[i].resource->type));
		printf("class: %hd\n",ntohs(answers[i].resource->_class));
		printf("ttl: %d\n",ntohs(answers[i].resource->ttl));
		printf("length: %hd\n",ntohs(answers[i].resource->data_len));
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1) //print ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
				printf("%hd\n", reader[j]);
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		}
		else
		{
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	//read authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		auth[i].rdata=ReadName(reader,buf,&stop);
		reader+=stop;
	}

	//read additional, same to previous code
	for(i=0;i<ntohs(dns->add_count);i++)
	{
		addit[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		if(ntohs(addit[i].resource->type)==1)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
			addit[i].rdata=ReadName(reader,buf,&stop);
			reader+=stop;
		}
	}

	//print answers
	printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
	for(i=0 ; i < ntohs(dns->ans_count) ; i++)
	{
		printf("Name : %s ",answers[i].name);

		if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
		{
			long *p;
			p=(long*)answers[i].rdata;
			a.sin_addr.s_addr=(*p); //working without ntohl
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		
		if(ntohs(answers[i].resource->type)==T_CNAME) 
		{
			//Canonical name for an alias
			printf("has alias name : %s",answers[i].rdata);
		}

		printf("\n");
	}

	//print authorities
	printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
	for( i=0 ; i < ntohs(dns->auth_count) ; i++)
	{
		
		printf("Name : %s ",auth[i].name);
		if(ntohs(auth[i].resource->type)==2)
		{
			printf("has nameserver : %s",auth[i].rdata);
		}
		printf("\n");
	}

	//print additional resource records
	printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
	for(i=0; i < ntohs(dns->add_count) ; i++)
	{
		printf("Name : %s ",addit[i].name);
		if(ntohs(addit[i].resource->type)==1)
		{
			long *p;
			p=(long*)addit[i].rdata;
			a.sin_addr.s_addr=(*p);
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		printf("\n");
	}
	return;
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