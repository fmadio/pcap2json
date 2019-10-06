//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The Creative Commons BY-NC 4.0 International License see LICENSE file for details 
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
// 2019/02/02 : 
// sudo stream_cat --chunked --pktslice 72 --cpu 13 interop17_20190202_0902 | ./pcap2json  --config /mnt/store0/etc/pcap2json.config | wc -l
// total lines 2730178 
//
// 2019/10/06:
//
// --output-null (stdin non chunked)
//   Total Time: 283.36 sec RawInput[Wire 0.034 Gbps Capture 0.034 Gbps 0.046 Mpps] Output[0.000 Gbps] TotalLine:1345265 4748 Line/Sec 
//   Total Time: 281.77 sec RawInput[Wire 0.034 Gbps Capture 0.034 Gbps 0.047 Mpps] Output[0.000 Gbps] TotalLine:1345265 4774 Line/Sec 
//
// --output-null (chunked)
//   Total Time: 25.41 sec RawInput[Wire 31.051 Gbps Capture 4.832 Gbps 3.416 Mpps] Output[0.000 Gbps] TotalLine:1404882 55296 Line/Sec
//   Total Time: 25.87 sec RawInput[Wire 30.493 Gbps Capture 4.746 Gbps 3.354 Mpps] Output[0.000 Gbps] TotalLine:1404882 54302 Line/Sec
//
// --output-null (shmring)
//   Total Time: 22.39 sec RawInput[Wire 35.231 Gbps Capture 5.483 Gbps 3.876 Mpps] Output[0.000 Gbps] TotalLine:1404882 62741 Line/Sec    
//   Total Time: 22.64 sec RawInput[Wire 34.852 Gbps Capture 5.424 Gbps 3.834 Mpps] Output[0.000 Gbps] TotalLine:1404882 62066 Line/Sec 

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

	u8*					BufferCompress;							// compressed output buffer 
	u32					BufferCompressMax;

	u8*					BufferRecv;								// recv buffer replies
	u32					BufferRecvMax;							// maximum recv size

	u32					Lock;									// dont let LineAdd write to an outputing buffer
	volatile bool		IsReady;								// buffer ready for processing	

	int					fd;										// file handle for output buffer map
	u8*					BufferMap;

} Buffer_t;

typedef struct OutputThread_t
{
	int 			Sock;										// Thread specific ES server connection socket fd
	void* 			Out;										// Output_t structure reference pointer
} OutputThread_t;


typedef struct Output_t
{
	volatile u32		BufferPut;								// buffers current put 
	volatile u32		BufferGet;								// buffer current get
	volatile u32		BufferFin;								// buffers finished 
	u32					BufferMask;
	u32					BufferMax;
	u32					BufferLock;								// mutual exclusion lock
	Buffer_t			BufferList[16*1024];					// buffer list 

	u32					MergeLock;								// mutal exclusion to merge multiple output blocks

	u64					TotalByte;								// total number of bytes down the wire

	u64					ByteQueued;								// bytes pushed onto the queue
	u64					ByteComplete;							// bytes sucessfully pushed 

	u64					LineQueued;								// lines queued
	u64					LineComplete;							// lines completed

	u64					ESPushByte;								// stats on bytes pushed
	u64					ESPushCnt;								// stats number of unique pushes 
																// these get reset by Output_stats 
	u64					ESPushTSC;								// TSC of last reset. allows bandwidth calcuation

	FILE*				FileTXT;								// output text file	

	bool				ESPush;									// enable direct ES push
	u32					ESHostCnt;								// number of registered ES hosts
	u32					ESHostPos;								// current ES push target
	u8					ESHostName[ESHOST_MAX][256];			// ip host name of ES
	u32					ESHostPort[ESHOST_MAX];					// port of ES
	bool				ESHostIsNotWorking[ESHOST_MAX];			// set this if the host is found not working
	u32					ESPushTotal[128];						// total number of ES pushes	
	u32					ESPushError[128];						// total number of ES errors 
	u32					ESHostLock;								// ES host lock to update ESHostPos

	bool				IsCompress;								// enable compression

	OutputThread_t		OutputThread[128];						// thread specific data
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

extern bool 			g_Verbose;
extern u32				g_ESTimeout;
extern bool				g_Output_Keepalive;

static volatile bool	s_Exit 			= false;
static u32				s_MergeMax		= 64;					// merge up to 64 x 1MB buffers for 1 bulk upload
static bool				s_IsESNULL 		= false;				// debug flag to remove the ES output stall

//-------------------------------------------------------------------------------------------
// poormans mini linter
static bool JSONLint(u8* Buffer, u32 Length)
{
	u32 QuoteCnt = 0;
	u32 BraceIn = 0;
	u32 BraceOut = 0;
	u32 InString = 0;
	bool IsError = false;

	if (Buffer[0] != '{') IsError = true;

	for (int i=0; i < Length; i++)
	{
		if (Buffer[i] == '"')
		{
			QuoteCnt++;
			InString ^= 1;
		}

		if ((Buffer[i] == '{') || (Buffer[i] == ','))
		{
			if (InString)
			{
				//printf("%i %i\n", i, InString);
				IsError = true;
			}
		}

		if (Buffer[i] == '{') BraceIn++; 
		if (Buffer[i] == '}')
		{
			BraceOut++; 

			// check for bulk requests terminiated by newline 
			if (BraceIn == BraceOut)
			{
				if (Buffer[i+1] != '\n')
				{
					printf("no newline\n");
					IsError = true;	
				}
			}
		}

		/*
		if (B->Buffer[i] == '{')
		{
			if (InString) IsError = true;
		}
		if (B->Buffer[i] == '}')
		{
			if (InString) IsError = true;
		}
		*/
	}

	if ((QuoteCnt &1) || (IsError) || (BraceIn != BraceOut) )
	{
		return false;
	}
	return true;
}

//-------------------------------------------------------------------------------------------

Output_t* Output_Create(bool IsNULL, 
						bool IsSTDOUT, 
						bool IsESOut, 
						bool IsCompress, 
						bool IsESNULL, 
						u32 Output_BufferCnt,
						u8* QueuePath,
						s32* CPUMap)
{
	fprintf(stderr, "OutputBuffer Config\n");
	fprintf(stderr, "   IsNULL        : %i\n", IsNULL); 
	fprintf(stderr, "   IsStdOut      : %i\n", IsSTDOUT); 
	fprintf(stderr, "   IsESNULL      : %i\n", IsESNULL); 
	fprintf(stderr, "   IsESPush      : %i\n", IsESOut); 
	fprintf(stderr, "   IsCompress    : %i\n", IsCompress); 
	fprintf(stderr, "   QueuePath     : %s\n", QueuePath); 

	Output_t* O = memalign(4096, sizeof(Output_t));
	memset(O, 0, sizeof(Output_t));	

	O->BufferPut		= 0;
	O->BufferGet		= 0;
	O->BufferMax		= Output_BufferCnt;
	O->BufferMask		= O->BufferMax - 1;

	u64 MemoryAlloc		= 0;	

	for (int i=0; i < O->BufferMax; i++)
	{
		// init buffer
		Buffer_t* B				= &O->BufferList[i];
		B->BufferPos			= 0;
		B->BufferMax 			= kMB(1); 

		B->BufferLine			= 0;
		B->IsReady				= false;

		// file backed queue
		if (QueuePath != NULL)
		{
			// map a file
			u8 FileName[128];
			sprintf(FileName, "%s/output_%04i.bin", QueuePath, i);

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
		}
		// RAM backed
		else
		{
			B->BufferMap = malloc( B->BufferMax * 3);
			assert(B->BufferMap != NULL);

			MemoryAlloc	+= B->BufferMax * 3;
		}

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

	// enable stdout writing 
	if (IsSTDOUT)
	{
		O->FileTXT		= stdout;
	}
	if (IsNULL)
	{
		O->FileTXT		= fopen("/dev/null", "w");
	}

	// ER null target
	s_IsESNULL = IsESNULL;

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
		O->OutputThread[i].Sock = -1;
		O->OutputThread[i].Out  = O;
		pthread_create(&O->PushThread[i], NULL, Output_Worker, (void*)&O->OutputThread[i]);
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
	fprintf(stderr, "   MemoryAlloc   : %i MB\n", (u32)(MemoryAlloc / kMB(1)) );	

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

		if (s_Exit) break;
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
// calcuuated the next ES Host to send bulk updload to
static u32 FindESHostPos(Output_t* Out)
{
	// case of --es-null where no outputs are specified
	if (Out->ESHostCnt == 0) return 0;

	sync_lock(&Out->ESHostLock, 50);
	u32 ESHostPos	= Out->ESHostPos;
	Out->ESHostPos	= (Out->ESHostPos + 1) % Out->ESHostCnt;

	for (u32 ESHostCnt=Out->ESHostCnt; ESHostCnt > 0; ESHostCnt--)
	{
		if (Out->ESHostIsNotWorking[Out->ESHostPos] == 0) break;
		Out->ESHostPos = (Out->ESHostPos + 1) % Out->ESHostCnt;
	}

	if (Out->ESHostIsNotWorking[Out->ESHostPos])
	{
		fprintf(stderr, "All ES hosts seems down !!\n");
		sync_unlock(&Out->ESHostLock);
		exit(-1);
	}
	sync_unlock(&Out->ESHostLock);

	return ESHostPos;
}

//-------------------------------------------------------------------------------------------
// Connect tcp socket to the specified ES host 
static int ConnectToES(u8* IPAddress, u32 Port)
{
	int Sock = socket(AF_INET, SOCK_STREAM, 0);
	assert(Sock > 0);

	// listen address
	struct sockaddr_in	BindAddr;					// bind address for acks
	memset((char *) &BindAddr, 0, sizeof(BindAddr));

	BindAddr.sin_family 		= AF_INET;
	BindAddr.sin_port 			= htons(Port);
	BindAddr.sin_addr.s_addr 	= inet_addr(IPAddress);

	// connect call should not hang for longer duration
	struct timeval tv = { g_ESTimeout / 1000, (g_ESTimeout % 1000)*1000 }; // 2 seconds
	setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
	setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&tv, sizeof(struct timeval));

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
		close(Sock);
		return -1;
	}

	// set timeout for connect
	int timeout = g_ESTimeout;  // user timeout in milliseconds [ms]
	ret = setsockopt (Sock, SOL_TCP, TCP_USER_TIMEOUT, (char*) &timeout, sizeof (timeout));
	if (ret < 0)
	{
		fprintf(stderr, "TCP_USER_TIMEOUT failed: %i %i %s\n", ret, errno, strerror(errno));
	}
	return Sock;
}

//-------------------------------------------------------------------------------------------
// directly push the json data to ES
void BulkUpload(OutputThread_t *T, u32 BufferIndex, u32 BufferCnt, u32 CPUID)
{
	Output_t* Out	= (Output_t*)T->Out;

	// output buffer
	u32 RawLength	 	= 0; 
	u32 RawLine			= 0;
	for (int i=0; i < BufferCnt; i++)
	{
		Buffer_t* B		= &Out->BufferList[ (BufferIndex + i) & Out->BufferMask];	

		RawLength		+= B->BufferPos;
		RawLine			+= B->BufferLine;
		//assert(B->IsReady == true);
	}

	// no compression for now
	u32 BulkLength		= RawLength; 

// force an ES error
//Bulk[RawLength/2] = '{';

	// if theres nothing to send then skip
	// NOTE* happens on timeout flushe just after a real flush 
	if (RawLength == 0) goto cleanup;

	/*
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
	*/

	u64 TSC1 = rdtsc();
	u64 TSC2 = TSC1;

	// not null es host
	if (!s_IsESNULL)
	{
		// work out which is the next ES Host
		u32 ESHostPos	= FindESHostPos(Out);
		u8* IPAddress	= Out->ESHostName[ESHostPos];
		u32 Port 		= Out->ESHostPort[ESHostPos];

		int error = 0;
		socklen_t len = sizeof (error);

		// check error on existing socket, otherwise create new socket
		if (T->Sock < 0 || getsockopt(T->Sock, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0)
		{
			if (T->Sock > 0) close(T->Sock);
			T->Sock = ConnectToES(IPAddress, Port);
			if (T->Sock == -1)
			{
				Out->ESHostIsNotWorking[ESHostPos]  = 1;
				goto cleanup;
			}
		}

		// generate Headers for ES POST
		u8 Header[16*1024];
		u32 HeaderPos = 0;

		u8 Footer[16*1024];
		u32 FooterPos = 0;

		// send trailing line feed
		FooterPos += sprintf(Footer + FooterPos, "\r\n");

		// HTTP request
		HeaderPos += sprintf(Header + HeaderPos, "POST /_bulk HTTP/1.1\r\n");

		HeaderPos += sprintf(Header + HeaderPos, "Content-Type: application/x-ndjson\r\n");

		HeaderPos += sprintf(Header + HeaderPos, "Connection: keep-alive\r\n");

		HeaderPos += sprintf(Header + HeaderPos, "Content-Length: %i\r\n", BulkLength);

		if (Out->IsCompress)
		{
			HeaderPos += sprintf(Header + HeaderPos, "Content-Encoding: gzip\r\n");
		}

		// no footer for compressed data 
		HeaderPos += sprintf(Header + HeaderPos, "\r\n");

		// send header
		int hlen = SendBuffer(T->Sock, Header, HeaderPos);
		assert(hlen == HeaderPos);

		// send body for all blocks
		for (int i=0; i < BufferCnt; i++)
		{
			Buffer_t* B = &Out->BufferList[ (BufferIndex + i) & Out->BufferMask];	

			int blen = SendBuffer(T->Sock, B->Buffer, B->BufferPos);
			if (blen != B->BufferPos)
			{
				printf("ERROR: Send %i %i : %i %i\n", blen, B->BufferPos, i, BufferCnt);
			}
			//assert(blen == B->BufferPos);
			//assert(JSONLint(B->Buffer, B->BufferPos));
		}

		// send footer 
		int flen = SendBuffer(T->Sock, Footer, FooterPos);
		assert(flen == FooterPos);

		// update stats
		__sync_fetch_and_add(&Out->TotalByte, HeaderPos + BulkLength + FooterPos);

		// total cycles for sending
		TSC2 = rdtsc();
		Out->WorkerTSCSend[CPUID] += TSC2 - TSC1;

		//printf("hlen: %i\n", hlen);
		//printf("blen: %i %i\n", blen, BulkLength);
		//printf("flen: %i\n", flen);

		// use the compress buffer for the response
		u8* RecvBuffer 		= Out->BufferList[ BufferIndex & Out->BufferMask ].BufferRecv;
		u32 RecvBufferMax 	= 16*1024; //Out->BufferList[ BufferIndex & Out->BufferMask ].BufferRecvMax;

		// if thers nothing in the buffer, ensure printf still has asciiz
		strcpy(RecvBuffer, "recv error");

		// get ES response, use the compressed buffer as the recv 
		int RecvBufferLen 	= 0;
		int ExpectBufferLen = 0;
		u32 TotalLength		= RecvBufferMax;
		while (RecvBufferLen < RecvBufferMax)
		{
			//printf("recv: %i %i\n", RecvBufferLen, TotalLength);
			int rlen = recv(T->Sock, RecvBuffer + RecvBufferLen, TotalLength - RecvBufferLen, 0);
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
				//Hexdump("Raw",		B->Buffer, 	B->BufferPos);
				Hexdump("Footer",   Footer, 	FooterPos);
			}	
			printf("[%lu] error on socket, closing socket fd: %d\n", pthread_self(), T->Sock);
			close(T->Sock);
			T->Sock = -1;
		}
		if (g_Output_Keepalive == true)
		{
			// read all the data from Sock otherwise it may hurt the subsequent send
			u8 tmp[10240];
			while (1)
			{
				int rlen = recv(T->Sock, tmp, sizeof(tmp), 0);
				if (rlen <= 0) break;
			}
		}
		else
		{
			// If not keep-alive then everytime we will make a new connection
			close(T->Sock);
			T->Sock = -1;
		}
	}

	u64 TSC3 = rdtsc();
	Out->WorkerTSCRecv[CPUID] += TSC3 - TSC2;

	// update counts
	Out->ESPushTotal[CPUID] += 1;

	// update completed bytes
	__sync_fetch_and_add(&Out->ByteComplete, RawLength);

	// udpate total lines
	__sync_fetch_and_add(&Out->LineComplete, RawLine);

	// total bulk uploads
	__sync_fetch_and_add(&Out->ESPushByte, RawLength);
	__sync_fetch_and_add(&Out->ESPushCnt,  1);

cleanup:
	// release the buffers
	for (int i=0; i < BufferCnt; i++)
	{
		Buffer_t* B		= &Out->BufferList[ (BufferIndex + i) & Out->BufferMask ];	

		// no need to reset the buffer 
		//memset(B->Buffer, 0, B->BufferPos);
		B->BufferLine 	= 0;
		B->BufferPos 	= 0;

		__asm__ volatile("sfence");
		B->IsReady		= false;
	}

	// update completion count
	__sync_fetch_and_add(&Out->BufferFin, BufferCnt);
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

	fprintf(stderr, "Output Join\n");
	for (int i=0; i < Out->CPUActiveCnt; i++)
	{
		fprintf(stderr, "  Worker %i\n", i);
		pthread_join(Out->PushThread[i], NULL);
	}
	fprintf(stderr, "Output Close\n");

	fprintf(stderr, "  Total Byte Queue   : %lli\n", Out->ByteQueued);
	fprintf(stderr, "  Total Byte Complete: %lli\n", Out->ByteComplete);

	fprintf(stderr, "  Total Line Queue   : %lli\n", Out->LineQueued);
	fprintf(stderr, "  Total Line Complete: %lli\n", Out->LineComplete);
}

//-------------------------------------------------------------------------------------------

u64 Output_TotalByteSent(Output_t* Out)
{
	return Out->TotalByte;
}

//-------------------------------------------------------------------------------------------

u64 Output_TotalLine(Output_t* Out)
{
	return Out->LineComplete;
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

u64 Output_BufferAdd(Output_t* Out, u8* Buffer, u32 BufferLen, u32 LineCnt)
{
	// drop null buffers
	if (BufferLen == 0) return 0;

	u64 TSC0 = 0;
	u64 TSC1 = 0;

	// write to a text file
	if (Out->FileTXT)
	{
		fprintf(Out->FileTXT, Buffer);
		Out->LineComplete += LineCnt;
	}

	// push directly to ES
	u64 SyncTopTSC 		= 0; 
	u64 SyncLocalTSC 	= 0;
	if (Out->ESPush)
	{
		// block until push has space to new queue entry 
		TSC0 = rdtsc();
		Buffer_t* B 	= NULL; 
		while (true)
		{
			// acquire a buffer 
			u64 SyncTopTSC 	= sync_lock(&Out->BufferLock, 50); 

			u64 Put 		= Out->BufferPut;

			// check theres space at head
			bool IsStall 	= false;
			if ((Put - Out->BufferFin) > (Out->BufferMax - Out->CPUActiveCnt - s_MergeMax))
			{
				IsStall = true;
			}
			else
			{
				// theres space so allocate
				Out->BufferPut 	+= 1; 
			}
			sync_unlock(&Out->BufferLock);

			// got an entry then exit
			if (!IsStall)
			{
				B = &Out->BufferList[Put & Out->BufferMask];
				break;
			}
			//usleep(0);
			ndelay(100);
		}
		TSC1 = rdtsc();

		// wait for buffer to be fully freeed
		// as the above flow control is not fully thread safe
		// need to stall here on the individual buffer also
		while (true)
		{
			if (B->IsReady == false) break;
			usleep(0);
		}

		// fill the buffer + complete it 
		memcpy(B->Buffer, Buffer, BufferLen);
		B->BufferPos 	= BufferLen;
		B->BufferLine 	= LineCnt;

		__asm__ volatile("sfence");
		B->IsReady 		= true;
	}

	// update total line stats
	__sync_fetch_and_add(&Out->LineQueued, LineCnt);

	// total bytes queued
	__sync_fetch_and_add(&Out->ByteQueued, BufferLen);

	return (TSC1 - TSC0) + SyncTopTSC + SyncLocalTSC;
}

//-------------------------------------------------------------------------------------------

static void* Output_Worker(void * user)
{
	OutputThread_t *T = (OutputThread_t *)user;
	Output_t* Out = (Output_t*)T->Out;

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
			// attempt to merge as many output blocks as possible
			sync_lock(&Out->MergeLock, 50); 

			u32 BufferBase 	= Out->BufferGet;
			Get 			= BufferBase; 

			// merge up to a 64MB bulk upload size 
			for (int b=0; b < s_MergeMax; b++)	
			{
				// reached end of chain 
				if (Get == Out->BufferPut) break;

				// attempt to get the next one
				Buffer_t* B = &Out->BufferList[ Get & Out->BufferMask ];

				// buffer not ready exit the chain 
				if (!B->IsReady) break;

				// add this buffer + go to next buffer
				Get++;
			}

			// update new get ptr
			Out->BufferGet = Get;

			sync_unlock(&Out->MergeLock);

			// total number of output buffers
			u32 BufferCnt = Get - BufferBase;
			if (BufferCnt > 0)
			{
				//if (BufferCnt > 1) printf("merge: %i\n", BufferCnt);

				// bulk upload
				u64 TSC2 = rdtsc();

				// output multiple blocks
				BulkUpload(T, BufferBase, BufferCnt, CPUID);

				u64 TSC3 = rdtsc(); 
				Out->WorkerTSCTop[CPUID] += TSC3 - TSC2;
			}
		}

		u64 TSC1 = rdtsc(); 
		Out->WorkerTSCTotal[CPUID] += TSC1 - TSC0;
	}
	close(T->Sock);
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
					u64*   pPendingB,
					u64*   pPushSizeB,
					u64*   pPushBps
){
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

	// time since last print
	float dT		= tsc2ns(rdtsc() - Out->ESPushTSC) / 1e9;

	// how much output data is pending
	u64 BytePending = Out->ByteQueued - Out->ByteComplete;
	if (pPendingB) pPendingB[0] = BytePending;

	// average upload size
	float AvgUpload = Out->ESPushByte * inverse(Out->ESPushCnt);

	// average upload bits / sec 
	float Bps = (Out->ESPushByte * 8.0) / dT;

	if (pPushSizeB) pPushSizeB[0] = AvgUpload;
	if (pPushBps) pPushBps[0] = Bps;
	if (IsReset)
	{
		Out->ESPushByte = 0;
		Out->ESPushCnt 	= 0;
		Out->ESPushTSC	= rdtsc();
	}
}
