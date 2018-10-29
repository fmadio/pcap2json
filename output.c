//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
// 
// reference pcap interop17_small (10GB)
//
// Total Packets: 9233139
// TotalBytes     : 10737417323
// TotalPackets   : 9233139
// PayloadCRC     : 39928dfab939e932
//
// output of bulk upload 
//
// 2018/10/26 : interop17_small dataset (10GB) - 429 sec :           : serialized upload
// 2018/10/26 : interop17_small dataset (10GB) - 287 sec :           : 1 worker (uncompressed)
// 2018/10/27 : interop17_small dataset (10GB) - 302 sec :           : 1 worker (best speed compress)
// 2018/10/27 : interop17_small dataset (10GB) - 127 sec :           : 4 worker (best speed compress)
// 2018/10/27 : interop17_small dataset (10GB) - 123 sec : 0.642Gbps : 8 worker (default compress)
//
// 2018/10/25 : interop17 dataset (100GB) : 78min
// 2018/10/27 : interop17 dataset (100GB) : 22min : 8 worker (default compress)
// 2018/10/27 : interop17 dataset (100GB) : 25min : 8 worker (no compress)
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
#include "miniz.h"

//---------------------------------------------------------------------------------------------

typedef struct
{
	u8*					Buffer;									// output buffer
	u32					BufferPos;								// current output pos
	u32					BufferMax;								// max buffer pos
	u32					BufferLine;								// total line count
	u32					BufferLineMax;							// maximum line count 


	u8*					BufferCompress;							// compressed output buffer 
	u32					BufferCompressMax;

} Buffer_t;

typedef struct Output_t
{
	volatile u32		BufferPut;								// buffers current put 
	volatile u32		BufferGet;								// buffer current get
	u32					BufferMask;
	u32					BufferMax;
	Buffer_t			BufferList[128];						// buffer list 
	u64					TotalByte[128];							// total amount of bytes sent by each buffer^ 
	u64					TotalLine;								// total number of lines output

	FILE*				FileTXT;								// output text file	

	bool				ESPush;									// enable direct ES push
	u8					ESHostName[256];						// ip host name of ES
	u32					ESHostPort;								// port of ES

	bool				IsCompress;								// enable compression

	pthread_t   		PushThread[16];							// worker thread list

} Output_t;

static void* Output_Worker(void * user);

//-------------------------------------------------------------------------------------------

Output_t* Output_Create(bool IsSTDOUT, bool IsESOut, u8* ESHostName, u32 ESHostPort, bool IsCompress)
{
	Output_t* O = malloc(sizeof(Output_t));
	memset(O, 0, sizeof(Output_t));	

	O->BufferPut		= 0;
	O->BufferGet		= 0;
	O->BufferMax		= 16;
	O->BufferMask		= 0xf;

	for (int i=0; i < O->BufferMax; i++)
	{
		Buffer_t* B				= &O->BufferList[i];
		B->BufferPos			= 0;
		B->BufferMax 			= kMB(16); 

		B->BufferLine			= 0;
		B->BufferLineMax		= 100e3;

		B->Buffer				= malloc( B->BufferMax );
		assert(B->Buffer != NULL);
		memset(B->Buffer, 0, B->BufferMax);

		B->BufferCompressMax	= kMB(16);
		B->BufferCompress		= malloc( B->BufferCompressMax ); 
		assert(B->BufferCompress != NULL);
	}

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

		O->IsCompress	= IsCompress;
	}

	// create worker threads
	pthread_create(&O->PushThread[0], NULL, Output_Worker, (void*)O);
	pthread_create(&O->PushThread[1], NULL, Output_Worker, (void*)O);
	pthread_create(&O->PushThread[2], NULL, Output_Worker, (void*)O);
	pthread_create(&O->PushThread[3], NULL, Output_Worker, (void*)O);
	pthread_create(&O->PushThread[4], NULL, Output_Worker, (void*)O);
	pthread_create(&O->PushThread[5], NULL, Output_Worker, (void*)O);
	pthread_create(&O->PushThread[6], NULL, Output_Worker, (void*)O);
	pthread_create(&O->PushThread[7], NULL, Output_Worker, (void*)O);

	// Gen1 mapping
	//u32 CPUMap[8] = { 5, 5, 5, 5, 5+6, 5+6, 5+6, 5+6};

	// Gen2 mapping
	u32 CPUMap[8] = {24, 24, 24, 24, 25, 25, 25, 25};

	for (int i=0; i < 8; i++)
	{
		cpu_set_t Thread0CPU;
		CPU_ZERO(&Thread0CPU);
		CPU_SET (CPUMap[i], &Thread0CPU);
		pthread_setaffinity_np(O->PushThread[i], sizeof(cpu_set_t), &Thread0CPU);
	}

	return O;
}

//-------------------------------------------------------------------------------------------
// directly push the json data to ES

void BulkUpload(Output_t* Out, u32 BufferIndex)
{
	u8* IPAddress 	= Out->ESHostName; 
	u32 Port 		= Out->ESHostPort;	
	
	Buffer_t* B		= &Out->BufferList[ BufferIndex ];	

	// raw json block to be uploaded
	u8* Bulk		= B->Buffer;
	u32 BulkLength	= B->BufferPos;

	// compress the raw data
	if (Out->IsCompress)
	{
		ulong CompressLength = B->BufferCompressMax;

		u8* GZHeader = B->BufferCompress;

		//u32 CompressLevel = MZ_BEST_SPEED;
		u32 CompressLevel = MZ_DEFAULT_LEVEL;
		//u32 CompressLevel = MZ_BEST_COMPRESSION;

		// need to ignore the first 2 bytes of the compressed output, as its packaged with zlib headers
		int zret = compress2(GZHeader + 10 - 2, &CompressLength, Bulk, BulkLength, CompressLevel);	
		assert(zret == Z_OK);

		// write gzip header
		GZHeader[0] = 0x1F;
		GZHeader[1] = 0x8B;
		GZHeader[2] = 8;
		GZHeader[3] = 0;
		GZHeader[4] = 0;
		GZHeader[5] = 0;
		GZHeader[6] = 0;
		GZHeader[7] = 0;
		GZHeader[8] = 0;
		GZHeader[9] = 0xFF;

		// remove zlip frame
		// NOTE: compression starts @ -2 offset of the header
		CompressLength -= 2;
		CompressLength -= 4;

		// originial crc
		mz_ulong crc = mz_crc32(MZ_CRC32_INIT, Bulk, BulkLength);

		// write gzip footer
		u8* GZFooter = GZHeader + 10 + CompressLength;
		GZFooter[0] = (crc >>  0) & 0xFF;
		GZFooter[1] = (crc >>  8) & 0xFF;
		GZFooter[2] = (crc >> 16) & 0xFF;
		GZFooter[3] = (crc >> 24) & 0xFF;
		GZFooter[4] = (BulkLength >>  0)& 0xFF;
		GZFooter[5] = (BulkLength >>  8) & 0xFF;
		GZFooter[6] = (BulkLength >> 16) & 0xFF;
		GZFooter[7] = (BulkLength >> 24) & 0xFF;

		/*
		FILE* F = fopen("ass.gz", "w");
		fwrite(B->BufferCompress, 10 + CompressLength + 8, 1, F);
		fclose(F);
		*/

		printf("Compressed: %lli B Raw %i B Ratio: x%.3f\n", CompressLength, BulkLength, BulkLength / (float)CompressLength );

		Bulk		= B->BufferCompress;
		BulkLength	= 10 + CompressLength + 8; 
	}

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

		fprintf(stderr, "Connection to [%s:%i] timed out... retry\n", IPAddress, Port);

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
	sprintf(Header + HeaderPos, "POST /_bulk HTTP/1.1\r\n"); 
	HeaderPos += strlen(Header + HeaderPos);

	sprintf(Header + HeaderPos, "Content-Type: application/x-ndjson\r\n");
	HeaderPos += strlen(Header + HeaderPos);

	sprintf(Header + HeaderPos, "Content-Length: %i\r\n", BulkLength);
	HeaderPos += strlen(Header + HeaderPos);

	if (Out->IsCompress)
	{
		sprintf(Header + HeaderPos, "Content-Encoding: gzip\r\n");
		HeaderPos += strlen(Header + HeaderPos);
	}

	// no footer for compressed data 
	sprintf(Header + HeaderPos, "\r\n");
	HeaderPos += strlen(Header + HeaderPos);

	// send header
	int hlen = send(Sock, Header, HeaderPos, MSG_NOSIGNAL);
	assert(hlen == HeaderPos);
	Out->TotalByte[BufferIndex] += HeaderPos;

	// send body
	int blen = send(Sock, Bulk, BulkLength, MSG_NOSIGNAL);
	assert(blen == BulkLength);
	Out->TotalByte[BufferIndex] += BulkLength;

	// send footer 
	int flen = send(Sock, Footer, FooterPos, MSG_NOSIGNAL);
	assert(flen == FooterPos);
	Out->TotalByte[BufferIndex] += FooterPos;

	//printf("hlen: %i\n", hlen);
	//printf("blen: %i %i\n", blen, BulkLength);
	//printf("flen: %i\n", flen);

	u8 RecvBuffer[4*1024];
	u32 RecvBufferMax = 4*1024;

	// get ES response, only grab a part of the message
	// as only checking for errors, dont need the full 
	// per item output list
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

	printf("[%s] [%s] %i Lines %iB\n", TookStr, ErrorStr, B->BufferLine, B->BufferPos);

	//RecvBuffer[250] = 0;
	//printf("%s\n", RecvBuffer);

	// shutdown the socket	
	close(Sock);

	// reset buffer
	B->BufferLine 	= 0;
	B->BufferPos 	= 0;
	memset(B->Buffer, 0, B->BufferMax);
}

//-------------------------------------------------------------------------------------------

void Output_Close(Output_t* Out)
{

}

//-------------------------------------------------------------------------------------------

u64 Output_TotalByteSent(Output_t* Out)
{
	u64 Byte = 0;
	for (int i=0; i < Out->BufferMax; i++)
	{
		Byte += Out->TotalByte[i];
	}
	return Byte;
}

//-------------------------------------------------------------------------------------------

u64 Output_TotalLine(Output_t* Out)
{
	return Out->TotalLine;
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
		Buffer_t* B = &Out->BufferList[Out->BufferPut];

		memcpy(B->Buffer + B->BufferPos, Buffer, BufferLen);
		B->BufferPos += BufferLen;

		B->BufferLine += 1;
		if ((B->BufferLine > B->BufferLineMax) || (B->BufferPos + kKB(16) > B->BufferMax))
		{
			// block until push has completed
			// NOTE: there may be 8 buffers/workers in progress so add bit 
			//       of extra padding in queuing behaviour
			while (((Out->BufferPut + 8 + 4) & Out->BufferMask) == Out->BufferGet)
			{
				usleep(10e3);
			}

			// add so the workers can push it
			//BulkUpload(Out, Out->BufferPut);
			Out->BufferPut = (Out->BufferPut + 1) & Out->BufferMask;
		}
	}
	Out->TotalLine++;
}

//-------------------------------------------------------------------------------------------

static void* Output_Worker(void * user)
{
	Output_t* Out = (Output_t*)user;
	while (true)
	{
		if (Out->BufferPut == Out->BufferGet)
		{
			usleep(1e3);
			continue;
		}

		// attempt to get the next one
		u32 Get = Out->BufferGet;
		Buffer_t* B = &Out->BufferList[ Get ];

		// fetch and process the next block 
		if (__sync_bool_compare_and_swap(&Out->BufferGet, Get, (Get + 1) & Out->BufferMask))
		{
			//Index = Get & N->Queue->Mask;
			//printf("process block G:%i P:%i\n", Get, Out->BufferPut);

			BulkUpload(Out, Get);	
		}
	}
	return NULL;
}
