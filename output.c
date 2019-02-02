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
#include <malloc.h>
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
#include "fProfile.h"

#define SOL_TCP 6  			// socket options TCP level
#define TCP_USER_TIMEOUT 18  // tcp timeout 

//---------------------------------------------------------------------------------------------

#define ESHOST_MAX		128										// max number of round robbin ES host targets

typedef struct
{
	u8*					Buffer;									// output buffer
	u32					BufferPos;								// current output pos
	u32					BufferMax;								// max buffer pos
	u32					BufferLine;								// total line count
	u32					BufferLineMax;							// maximum line count 

	u8*					BufferCompress;							// compressed output buffer 
	u32					BufferCompressMax;

	u8*					BufferRecv;								// recv buffer replies
	u32					BufferRecvMax;							// maximum recv size

	u32					Lock;									// dont let LineAdd write to an outputing buffer

	int					fd;										// file handle for output buffer map
	u8*					BufferMap;

} Buffer_t;

typedef struct Output_t
{
	volatile u32		BufferPut;								// buffers current put 
	volatile u32		BufferGet;								// buffer current get
	volatile u32		BufferFin;								// buffers finished 
	u32					BufferMask;
	u32					BufferMax;
	u32					BufferLock;								// mutual exclusion lock
	Buffer_t			BufferList[1024];						// buffer list 
	u64					TotalByte[1024];						// total amount of bytes sent by each buffer^ 
	u64					TotalLine;								// total number of lines output

	u64					FlushTimeout;							// flush atleast this nsec
	u64					FlushLastTS;							// time of last flush

	FILE*				FileTXT;								// output text file	

	bool				ESPush;									// enable direct ES push
	u32					ESHostCnt;								// number of registered ES hosts
	u32					ESHostPos;								// current ES push target
	u8					ESHostName[ESHOST_MAX][256];			// ip host name of ES
	u32					ESHostPort[ESHOST_MAX];					// port of ES
	u32					ESPushTotal[128];						// total number of ES pushes	
	u32					ESPushError[128];						// total number of ES errors 

	bool				IsCompress;								// enable compression

	pthread_t   		PushThread[128];						// worker thread list

	volatile u32		CPUActiveCnt;							// total number of active cpus

	volatile u64		WorkerTSCTotal[128];					// total TSC 
	volatile u64		WorkerTSCTop[128];						// cycles used for acutal data processing 
	volatile u64		WorkerTSCCompress[128];					// cycles spent for compression 
	volatile u64		WorkerTSCSend[128];						// cycles spent for tcp sending 
	volatile u64		WorkerTSCRecv[128];						// cycles spent for tcp recv

} Output_t;

static void* Output_Worker(void * user);

//-------------------------------------------------------------------------------------------

extern bool g_Verbose;

static volatile bool		s_Exit = false;

//-------------------------------------------------------------------------------------------

Output_t* Output_Create(bool IsNULL, 
						bool IsSTDOUT, 
						bool IsESOut, 
						bool IsCompress, 
						u32 Output_BufferCnt, 
						u32 Output_LineFlush, 
						u64 Output_TimeFlush, 
						u64 Output_ByteFlush, 
						s32* CPUMap)
{
	fprintf(stderr, "OutputBuffer Config\n");
	fprintf(stderr, "   IsNULL        : %i\n", IsNULL); 
	fprintf(stderr, "   IsES          : %i\n", IsSTDOUT); 
	fprintf(stderr, "   IsStdout      : %i\n", IsESOut); 
	fprintf(stderr, "   IsCompress    : %i\n", IsCompress); 
	fprintf(stderr, "   ByteFlush     : %lli\n", Output_ByteFlush);
	fprintf(stderr, "   LineFlush     : %lli\n", Output_LineFlush);
	fprintf(stderr, "   TimeFlush     : %lli\n", Output_TimeFlush);

	Output_t* O = memalign(4096, sizeof(Output_t));
	memset(O, 0, sizeof(Output_t));	

	O->BufferPut		= 0;
	O->BufferGet		= 0;
	O->BufferMax		= Output_BufferCnt;
	O->BufferMask		= O->BufferMax - 1;

	for (int i=0; i < O->BufferMax; i++)
	{
		// init buffer
		Buffer_t* B				= &O->BufferList[i];
		B->BufferPos			= 0;
		B->BufferMax 			= Output_ByteFlush; 

		B->BufferLine			= 0;
		B->BufferLineMax		= Output_LineFlush;

		// map a file
		u8 FileName[128];
		sprintf(FileName, "/mnt/store0/protocol/pcap2json/output_%04i.bin", i);

		// force file creation 
		B->fd = open(FileName, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU); 
		if (B->fd <= 0)
		{
			printf("failed to create output file %s: %i %i\n", FileName, B->fd, errno); 
			return NULL;
		}

		// new file so clear everything out 
		ftruncate(B->fd,  B->BufferMax * 3); 

		// shm mapping 
		B->BufferMap = mmap64(0, B->BufferMax * 3, PROT_READ|PROT_WRITE, MAP_SHARED, B->fd, 0);
		assert(B->BufferMap != NULL);

		// slice up the output buffer
		B->Buffer				= B->BufferMap + 0 * B->BufferMax;
		assert(B->Buffer != NULL);
		memset(B->Buffer, 0, B->BufferMax);

		B->BufferCompressMax	= B->BufferMax; 
		B->BufferCompress		= B->BufferMap + 1 * B->BufferMax;
		assert(B->BufferCompress != NULL);

		B->BufferRecvMax		= B->BufferMax; 
		B->BufferRecv			= B->BufferMap + 2 * B->BufferMax;
		assert(B->BufferRecv != NULL);
	}

	// timeout for flushing
	O->FlushLastTS			= 0;
	O->FlushTimeout			= Output_TimeFlush;

	// enable stdout writing 
	if (IsSTDOUT)
	{
		O->FileTXT		= stdout;
	}
	if (IsNULL)
	{
		O->FileTXT		= fopen("/dev/null", "w");
	}

	// direct ES push
	O->ESHostCnt = 0;
	O->ESHostPos = 0;
	if (IsESOut)
	{
		O->ESPush		= true;
		O->IsCompress	= IsCompress;
	}

	// create 32 worker threads
	u32 CoreCnt = 4;				// assume 4 cores for the output
	u32 CPUCnt 	= 0;
	for (int i=0; i < 32; i++)
	{
		pthread_create(&O->PushThread[i], NULL, Output_Worker, (void*)O); 
		CPUCnt++;
	}
	for (int i=0; i < CPUCnt; i++)
	{
		s32 CPU = CPUMap[i % CoreCnt];
		if (CPU < 0) continue;

		cpu_set_t Thread0CPU;
		CPU_ZERO(&Thread0CPU);
		CPU_SET (CPU, &Thread0CPU);
		pthread_setaffinity_np(O->PushThread[i], sizeof(cpu_set_t), &Thread0CPU);
	}

	return O;
}

//-------------------------------------------------------------------------------------------
// adds an output ES target
void Output_ESHostAdd(Output_t* Out, u8* HostName, u32 HostPort)
{
	strncpy(Out->ESHostName[Out->ESHostCnt], HostName, sizeof(Out->ESHostName[0]));
	Out->ESHostPort[Out->ESHostCnt]	= HostPort;

	Out->ESHostCnt++;
}

//-------------------------------------------------------------------------------------------
// send and block 
static int SendBuffer(int Sock, u8* Buffer, u32 BufferLength)
{
	u32 Pos = 0;
	while (Pos < BufferLength)
	{
		int slen = send(Sock, Buffer + Pos, BufferLength - Pos, MSG_NOSIGNAL);
		if (slen < 0)
		{
			printf("send failed: %i %i %s\n", slen, errno, strerror(errno));
			return -1;
		}
		Pos += slen;
	}
	return BufferLength;
}

//-------------------------------------------------------------------------------------------
static void Hexdump(u8* Desc, u8* Buffer, s32 Length)
{
	u32 Offset = 0;
	u32 LineStrPos = 0;
	u8 LineStr[128];
	while (Offset < Length)
	{
		if ((Offset & 0xf) == 0)
		{
			if (Offset != 0)
			{
				LineStr[LineStrPos] = 0;
				fprintf(stderr, "| %s\n", LineStr); 
			}
			fprintf(stderr, "%10s [%08x]: ", Desc, Offset); 

			LineStrPos = 0;	
		}

		u32 c = Buffer[Offset];
		u32 d = c; 
		if (c <   32) d = '.';
		if (c >= 127) d = '.';

		LineStr[LineStrPos++] = d;

		fprintf(stderr, "%02x ", c);
		Offset++;
	}
	while ((Offset & 0xF) != 0)	
	{
		fprintf(stderr, "%02s ", "  ");
		Offset++;
	}

	LineStr[LineStrPos] = 0;
	fprintf(stderr, "| %s\n", LineStr); 
	fprintf(stderr, "\n");
}

//-------------------------------------------------------------------------------------------
// directly push the json data to ES
void BulkUpload(Output_t* Out, u32 BufferIndex, u32 CPUID)
{
	u8* IPAddress 	= Out->ESHostName[Out->ESHostPos]; 
	u32 Port 		= Out->ESHostPort[Out->ESHostPos];	

	// round robbin ES target 
	Out->ESHostPos	= (Out->ESHostPos + 1) % Out->ESHostCnt;

	// output buffer
	Buffer_t* B		= &Out->BufferList[ BufferIndex ];	

	// raw json block to be uploaded
	u8* Bulk			= B->Buffer;
	u32 BulkLength		= B->BufferPos;
	u32 RawLength	 	= B->BufferPos;

// force an ES error
//Bulk[RawLength/2] = '{';

	// if theres nothing to send then skip
	// NOTE* happens on timeout flushe just after a real flush 
	if (RawLength == 0) return;

	// compress the raw data
	if (Out->IsCompress)
	{
		u64 TSC = rdtsc();

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

		//printf("Compressed: %lli B Raw %i B Ratio: x%.3f\n", CompressLength, BulkLength, BulkLength / (float)CompressLength );
		Bulk		= B->BufferCompress;
		BulkLength	= 10 + CompressLength + 8; 

		Out->WorkerTSCCompress[CPUID] += rdtsc() - TSC;
	}

	u64 TSC1 = rdtsc();

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

	// set timeout for connect 
	{
		int timeout = 10000;  // user timeout in milliseconds [ms]
		ret = setsockopt (Sock, SOL_TCP, TCP_USER_TIMEOUT, (char*) &timeout, sizeof (timeout));
		if (ret < 0)
		{
			fprintf(stderr, "TCP_USER_TIMEOUT failed: %i %i %s\n", ret, errno, strerror(errno));
		}
	}
	// set timeout for read/write 
	{
		struct timeval timeout;      
		timeout.tv_sec 	= 10;
		timeout.tv_usec = 0;

		ret = setsockopt (Sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		if (ret < 0)
		{
			fprintf(stderr, "SO_RECVTIMEO failed: %i %i %s\n", ret, errno, strerror(errno));
		}
		ret = setsockopt (Sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
		if (ret < 0)
		{
			fprintf(stderr, "SO_SENDTIMEO failed: %i %i %s\n", ret, errno, strerror(errno));
		}
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
	int hlen = SendBuffer(Sock, Header, HeaderPos);
	assert(hlen == HeaderPos);
	Out->TotalByte[BufferIndex] += HeaderPos;

	// send body
	int blen = SendBuffer(Sock, Bulk, BulkLength);
	assert(blen == BulkLength);
	Out->TotalByte[BufferIndex] += BulkLength;

	// send footer 
	int flen = SendBuffer(Sock, Footer, FooterPos);
	assert(flen == FooterPos);
	Out->TotalByte[BufferIndex] += FooterPos;

	// total cycles for sending
	u64 TSC2 = rdtsc();
	Out->WorkerTSCSend[CPUID] += TSC2 - TSC1;

	//printf("hlen: %i\n", hlen);
	//printf("blen: %i %i\n", blen, BulkLength);
	//printf("flen: %i\n", flen);

	// use the compress buffer for the response
	u8* RecvBuffer 		= B->BufferRecv;
	u32 RecvBufferMax 	= B->BufferRecvMax; 

	// if thers nothing in the buffer, ensure printf still has asciiz
	strcpy(RecvBuffer, "recv error");

	// get ES response, use the compressed buffer as the recv 
	int RecvBufferLen 	= 0;
	int ExpectBufferLen = 0;
	u32 TotalLength		= RecvBufferMax;
	while (RecvBufferLen < TotalLength)
	{
		//printf("recv: %i %i\n", RecvBufferLen, TotalLength);
		int rlen = recv(Sock, RecvBuffer + RecvBufferLen, TotalLength - RecvBufferLen, 0);
		if (rlen <= 0) break;

		// if content length has been parsed yet
		if (TotalLength == RecvBufferMax)
		{
			// attempt parse the HTTP reply to get content length 
			u8* ContentLengthStr = strstr(RecvBuffer, "content-length:");
			if (ContentLengthStr != NULL)
			{
				u32 LengthStrPos = 0;
				u8 LengthStr[8];
				ContentLengthStr += 16; 
				for (int i=0; i < 8; i++)
				{
					u32 c = *ContentLengthStr++;
					if (c == '\n') break;
					if (c == '\r') break;
					LengthStr[LengthStrPos++] = c; 
				}
				LengthStr[LengthStrPos++] = 0; 

				u32 ContentLength = atoi(LengthStr);
				TotalLength = ContentLength  + (ContentLengthStr - RecvBuffer) + 3;
				//printf("[%i] content length (%s) %i : %i\n", BufferIndex, LengthStr, ContentLength, TotalLength);
			}
		}
		RecvBufferLen += rlen;
		//printf("rlen: %i\n", rlen);
	}
	//printf("[%i] RecvLen: %i TotalLengh:%i \n", BufferIndex, RecvBufferLen, TotalLength);

	// asciiz it
	if (RecvBufferLen > 0) RecvBuffer[RecvBufferLen] = 0;

	// parse response for error field
	u32 JSONStrCnt = 0;
	u32 JSONStrPos = 0;
	u8  JSONStr[32][256];

	u32 RecvPos = 0;

	// skip HTTP Header, and find start of JSON data
	for (; RecvPos < RecvBufferLen; RecvPos++)
	{
		if (RecvBuffer[RecvPos] == '{') break;
	}
	RecvPos++;			// ignore first { encapsulation

	// parse partial JSON 
	// skip leading {
	for (; RecvPos < RecvBufferLen; RecvPos++)
	{
		u32 c = RecvBuffer[RecvPos];
		if (c == '\"') continue;				// fields are well defined
		if (c == ',')
		{
			JSONStr[JSONStrCnt][JSONStrPos] = 0; 
			JSONStrCnt++;
			JSONStrPos = 0;

			// only care about first few fields 
			if (JSONStrCnt > 16) break;
		}
		else
		{
			if (JSONStrPos < 256)
				JSONStr[JSONStrCnt][JSONStrPos++] = c; 
		}
	}
	JSONStr[JSONStrCnt][JSONStrPos] = 0; 
	JSONStrCnt++;

	u8* TookStr 	= JSONStr[0];
	u8* ErrorStr 	= JSONStr[1];

	// verbose logging
	//printf("%s:%i Raw:%8i Pak:%8i(x%5.2f) Lines:%10i [%-16s] [%s]\n", IPAddress, Port, RawLength, BulkLength, RawLength * inverse(BulkLength), B->BufferLine, TookStr, ErrorStr);
	//fflush(stdout);

	// check for errors
	if (strcmp(ErrorStr, "errors:false") != 0)
	{
		printf("ERROR: %i %i SendLen:%i\n", RecvBufferLen, strlen(RecvBuffer), BulkLength );
		for (int i=0; i < 8; i++)
		{
			printf("ERROR:  %i [%s]\n", i, JSONStr[i]);
		}

		// print full error response
		if (g_Verbose)
			printf("%s\n\n", RecvBuffer);

		// update error count
		// NOTE: should really be an atomic update
		Out->ESPushError[CPUID]++;

		// print hexdump of send buffer
		if (g_Verbose)
		{
			Hexdump("Header", 	Header, 	HeaderPos);
			Hexdump("Raw",		B->Buffer, 	B->BufferPos);
			Hexdump("Footer",   Footer, 	FooterPos);
		}	
	}

	// shutdown the socket	
	close(Sock);

	u64 TSC3 = rdtsc();
	Out->WorkerTSCRecv[CPUID] += TSC3 - TSC2;


	// reset buffer
	B->BufferLine 	= 0;
	B->BufferPos 	= 0;
	memset(B->Buffer, 0, B->BufferMax);

	// update counts
	Out->ESPushTotal[CPUID] += 1;

	// update completion count
	__sync_fetch_and_add(&Out->BufferFin, 1);
}

//-------------------------------------------------------------------------------------------

void Output_Close(Output_t* Out)
{
	// wait for workers to output 
	while (Out->BufferGet != Out->BufferPut)
	{
		usleep(0);
	}
	s_Exit = true;

	for (int i=0; i < Out->CPUActiveCnt; i++)
	{
		pthread_join(Out->PushThread[i], NULL);
	}
	printf("Output Close\n");
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

u64 Output_ESErrorCnt(Output_t* Out)
{
	u32 TotalError = 0; 
	for (int i=0; i < Out->CPUActiveCnt; i++)
	{
		TotalError += Out->ESPushError[i];
	}
	return TotalError; 
}

//-------------------------------------------------------------------------------------------

u64 Output_ESPushCnt(Output_t* Out)
{
	u32 TotalPush = 0; 
	for (int i=0; i < Out->CPUActiveCnt; i++)
	{
		TotalPush += Out->ESPushTotal[i];
	}
	return TotalPush; 
}

//-------------------------------------------------------------------------------------------

u64 Output_LineAdd(Output_t* Out, u8* Buffer, u32 BufferLen, u32 LineCnt)
{
	u64 TSC0 = 0;
	u64 TSC1 = 0;

	// multiple CPU call this function, ensure its
	// mutually exclusive output
	u64 SyncTopTSC = sync_lock(&Out->BufferLock, 50); 

	// write to a text file
	if (Out->FileTXT)
	{
		Out->TotalByte[0] += strlen(Buffer);
		fprintf(Out->FileTXT, Buffer);
	}

	// push directly to ES
	u64 SyncLocalTSC = 0;
	if (Out->ESPush)
	{
		Buffer_t* B = &Out->BufferList[Out->BufferPut];

		// ensure block is not currently being pushed 
		SyncLocalTSC = sync_lock(&B->Lock, 100);
		{
			memcpy(B->Buffer + B->BufferPos, Buffer, BufferLen);
			B->BufferPos += BufferLen;

			B->BufferLine += 1;

			// time to flush to ES?
			bool IsFlush = false;

			// flush every X lines
			IsFlush |= (B->BufferLine > B->BufferLineMax);

			// flush when near the end of the write buffer
			IsFlush |= (B->BufferPos + kKB(16) > B->BufferMax);

			// flush every X nanosec
			u64 TS = clock_ns();
			IsFlush |= ((TS - Out->FlushLastTS) > Out->FlushTimeout);
			if (IsFlush)
			{
				// block until push has completed
				// NOTE: there may be X buffers due to X workers in progress so add bit 
				//       of extra padding in queuing behaviour
				TSC0 = rdtsc();
				while (((Out->BufferPut + Out->CPUActiveCnt + 4) & Out->BufferMask) == Out->BufferGet)
				{
					usleep(0);
				}
				TSC1 = rdtsc();

				// add so the workers can push it
				//BulkUpload(Out, Out->BufferPut);
				Out->BufferPut = (Out->BufferPut + 1) & Out->BufferMask;

				// set last flush time
				Out->FlushLastTS = TS;
			}
		}
		sync_unlock(&B->Lock);
	}
	Out->TotalLine += LineCnt;

	sync_unlock(&Out->BufferLock);

	return (TSC1 - TSC0) + SyncTopTSC + SyncLocalTSC;
}

//-------------------------------------------------------------------------------------------

static void* Output_Worker(void * user)
{
	Output_t* Out = (Output_t*)user;

	// allocate a CPU number
	u32 CPUID = __sync_fetch_and_add(&Out->CPUActiveCnt, 1);
	while (!s_Exit)
	{
		u64 TSC0 = rdtsc(); 
		u32 Get = Out->BufferGet;
		if (Get == Out->BufferPut)
		{
			// nothing to process so zzzz 
			usleep(0);
		}
		else
		{
			// attempt to get the next one
			Buffer_t* B = &Out->BufferList[ Get ];

			// lock the buffer so LineAdd doesnt attempt to write
			// into it while the buffer is being pushed
			sync_lock(&B->Lock, 50); 
			{
				// fetch and process the next block 
				if (__sync_bool_compare_and_swap(&Out->BufferGet, Get, (Get + 1) & Out->BufferMask))
				{
					u64 TSC2 = rdtsc(); 

					BulkUpload(Out, Get, CPUID);	

					u64 TSC3 = rdtsc(); 
					Out->WorkerTSCTop[CPUID] += TSC3 - TSC2;
				}
			}
			sync_unlock(&B->Lock);
		}

		u64 TSC1 = rdtsc(); 
		Out->WorkerTSCTotal[CPUID] += TSC1 - TSC0;
	}
	return NULL;
}

//-------------------------------------------------------------------------------------------
// calculates the CPU usage of output worker threads.
// this is compress + HTTP framing + send  + recv + error processing time
void Output_Stats(	Output_t* Out, 
					bool IsReset, 
					float* pTop, 
					float* pCompress, 
					float* pSend,
					float* pRecv,
					u64*   pTotalCycle,
					u64*   pPendingB)
{
	u64 Total 	= 0;
	u64 Top 	= 0;
	u64 Comp 	= 0;
	u64 Send 	= 0;
	u64 Recv 	= 0;

	for (int i=0; i < Out->CPUActiveCnt; i++)
	{
		Total 	+= Out->WorkerTSCTotal[i];
		Top 	+= Out->WorkerTSCTop[i];
		Comp 	+= Out->WorkerTSCCompress[i];
		Send 	+= Out->WorkerTSCSend[i];
		Recv 	+= Out->WorkerTSCRecv[i];
	}	

	if (IsReset)
	{
		for (int i=0; i < Out->CPUActiveCnt; i++)
		{
			Out->WorkerTSCTotal[i]		= 0;
			Out->WorkerTSCTop[i]		= 0;
			Out->WorkerTSCCompress[i]	= 0;
			Out->WorkerTSCSend[i]		= 0;
			Out->WorkerTSCRecv[i]		= 0;
		}
	}
	if (pTop) 			pTop[0] 		= Top  * inverse(Total);
	if (pCompress) 		pCompress[0] 	= Comp * inverse(Total);
	if (pSend) 			pSend[0] 		= Send * inverse(Total);
	if (pRecv) 			pRecv[0] 		= Recv * inverse(Total);
	if (pTotalCycle)	pTotalCycle[0]	= Total;

	// how much output data is pending
	u32 BufferPending = Out->BufferPut - Out->BufferFin;
	u32 BufferPendingB = BufferPending  * Out->BufferMax;

	if (pPendingB) pPendingB[0] = BufferPendingB;
}
