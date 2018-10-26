//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
// 
// output of bulk upload 
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <locale.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "fTypes.h"

//---------------------------------------------------------------------------------------------

typedef struct Output_t
{
	u8*					Buffer;									// output buffer
	u32					BufferPos;								// current output pos
	u32					BufferMax;								// max buffer pos
	u32					BufferLine;								// total line count
	u32					BufferLineMax;							// maximum line count 

	FILE*				FileTXT;								// output text file	

	bool				ESPush;									// enable direct ES push
	u8					ESHostName[256];						// ip host name of ES
	u32					ESHostPort;								// port of ES

} Output_t;

//-------------------------------------------------------------------------------------------

Output_t* Output_Create(bool IsSTDOUT, bool IsESOut, u8* ESHostName, u32 ESHostPort)
{
	Output_t* O = malloc(sizeof(Output_t));
	memset(O, 0, sizeof(Output_t));	

	O->BufferPos		= 0;
	O->BufferMax 		= kMB(16); 

	O->BufferLine		= 0;
	O->BufferLineMax	= 100e3;

	O->Buffer			= malloc( O->BufferMax );

	// enable stdout writing 
	if (IsSTDOUT)
	{
		O->FileTXT		= stdout;
	}

	// direct ES push
	if (IsESOut)
	{
		O->ESPush		= true;
		strncpy(O->ESHostName, ESHostName, sizeof(O->ESHostName));
		O->ESHostPort	= ESHostPort;
	}

	return O;
}

//-------------------------------------------------------------------------------------------
// directly push the json data to ES

void BulkUpload(Output_t* Out)
{
	u8* IPAddress 	= Out->ESHostName; 
	u32 Port 		= Out->ESHostPort;	

	u8* Bulk		= Out->Buffer;
	u32 BulkLength	= Out->BufferPos;

	int Sock = socket(AF_INET, SOCK_STREAM, 0);
	assert(Sock > 0);
	
	// listen address 
	struct sockaddr_in	BindAddr;					// bind address for acks
	memset((char *) &BindAddr, 0, sizeof(BindAddr));

	BindAddr.sin_family 		= AF_INET;
	BindAddr.sin_port 			= htons(Port);
	BindAddr.sin_addr.s_addr 	= inet_addr(IPAddress);

	// retry connection a few times 
	int ret = -1;
	for (int r=0; r < 10; r++)
	{
		//bind socket to port
		ret = connect(Sock, (struct sockaddr*)&BindAddr, sizeof(BindAddr));
		if (ret >= 0) break;

		// connection timed out
		usleep(100e3);
	}
	if (ret < 0)
	{
		fprintf(stderr, "connect failed: %i %i : %s : %s:%i\n", ret, errno, strerror(errno), IPAddress, Port); 
		return;
	}

	// generate Headers for ES POST

	u8 Header[16*1024];
	u32 HeaderPos = 0;

	u8 Footer[16*1024];
	u32 FooterPos = 0;

	// send trailing line feed
	sprintf(Footer + FooterPos, "\r\n");
	FooterPos += strlen(Footer + FooterPos);

	// HTTP request
	//sprintf(Header + HeaderPos, "POST /_bulk?pretty HTTP/1.1\n"); 
	sprintf(Header + HeaderPos, "POST /_bulk HTTP/1.1\n"); 
	HeaderPos += strlen(Header + HeaderPos);

	sprintf(Header + HeaderPos, "Content-Type: application/x-ndjson\n");
	HeaderPos += strlen(Header + HeaderPos);

	sprintf(Header + HeaderPos, "Content-Length: %i\n", BulkLength + strlen(Footer));
	HeaderPos += strlen(Header + HeaderPos);

	sprintf(Header + HeaderPos, "\r\n\r\n");
	HeaderPos += strlen(Header + HeaderPos);

	// send header
	int hlen = send(Sock, Header, HeaderPos, MSG_NOSIGNAL);
	assert(hlen == HeaderPos);

	// send body
	int blen = send(Sock, Bulk, BulkLength, MSG_NOSIGNAL);
	assert(blen == BulkLength);

	// send footer 
	int flen = send(Sock, Footer, FooterPos, MSG_NOSIGNAL);
	assert(flen == FooterPos);

	//printf("hlen: %i\n", hlen);
	//printf("blen: %i %i\n", blen, BulkLength);
	//printf("flen: %i\n", flen);

	u8 RecvBuffer[16*1024];
	u32 RecvBufferMax = 16*1024;

	int rlen = recv(Sock, RecvBuffer, RecvBufferMax, 0);
	//printf("rlen: %i\n", rlen);


	// parse response for error field
	u32 TookStrPos = 0;
	u8  TookStr[128];

	u32 ErrorStrPos = 0;
	u8  ErrorStr[128];

	// find start of JSON
	u32 RecvPos = 0;
	for (int i=0; i < rlen; i++)
	{
		if (RecvBuffer[RecvPos] == '{') break;
		RecvPos++;
	}

	// copy "took" string
	for (int i=0; i < 128; i++)
	{
		if (RecvBuffer[RecvPos] == ',') break;
		TookStr[TookStrPos++] = RecvBuffer[RecvPos];
		RecvPos++;
	}
	TookStr[TookStrPos++] = 0; 

	// skip comma
	RecvPos++;

	// copy "errors" string
	for (int i=0; i < 128; i++)
	{
		if (RecvBuffer[RecvPos] == ',') break;
		ErrorStr[ErrorStrPos++] = RecvBuffer[RecvPos];
		RecvPos++;
	}
	ErrorStr[ErrorStrPos++] = 0;

	printf("[%s] [%s] %i Lines\n", TookStr, ErrorStr, Out->BufferLine);

	//RecvBuffer[250] = 0;
	//printf("%s\n", RecvBuffer);

	// shutdown the socket	
	close(Sock);
}

//-------------------------------------------------------------------------------------------

void Output_LineAdd(Output_t* Out, u8* Buffer, u32 BufferLen)
{
	// write to a text file
	if (Out->FileTXT)
	{
		fprintf(Out->FileTXT, Buffer);
	}

	// push directly to ES
	if (Out->ESPush)
	{
		memcpy(Out->Buffer + Out->BufferPos, Buffer, BufferLen);
		Out->BufferPos += BufferLen;

		Out->BufferLine += 1;
		if ((Out->BufferLine > Out->BufferLineMax) || (Out->BufferPos + kKB(16) > Out->BufferMax))
		{
			BulkUpload(Out);

			Out->BufferLine = 0;
			Out->BufferPos 	= 0;
			memset(Out->Buffer, 0, Out->BufferMax);
		}
	}
}
