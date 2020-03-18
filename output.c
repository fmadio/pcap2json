//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The Creative Commons BY-NC 4.0 International License see LICENSE file for details 
//
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
#include "fProfile.h"

//---------------------------------------------------------------------------------------------

typedef struct Output_t
{
	FILE*				FileTXT;								// output text file	

	u64					TotalByte;								// total number of bytes down the wire
	u64					TotalLine;								// lines completed 

	/*
	volatile u32		BufferPut;								// buffers current put 
	volatile u32		BufferGet;								// buffer current get
	volatile u32		BufferFin;								// buffers finished 
	u32					BufferMask;
	u32					BufferMax;
	u32					BufferLock;								// mutual exclusion lock
	Buffer_t			BufferList[16*1024];					// buffer list 

	u32					MergeLock;								// mutal exclusion to merge multiple output blocks


	u64					ByteQueued;								// bytes pushed onto the queue
	u64					ByteComplete;							// bytes sucessfully pushed 


	u64					ESPushByte;								// stats on bytes pushed
	u64					ESPushCnt;								// stats number of unique pushes 
																// these get reset by Output_stats 
	u64					ESPushTSC;								// TSC of last reset. allows bandwidth calcuation
	*/


	/*
	bool				ESPush;									// enable direct ES push
	u32					ESHostCnt;								// number of registered ES hosts
	u32					ESHostPos;								// current ES push target
	u8					ESHostName[ESHOST_MAX][256];			// ip host name of ES
	u32					ESHostPort[ESHOST_MAX];					// port of ES
	bool				ESHostIsNotWorking[ESHOST_MAX];			// set this if the host is found not working
	u32					ESPushTotal[256];						// total number of ES pushes	
	u32					ESPushError[256];						// total number of ES errors 
	u32					ESHostLock;								// ES host lock to update ESHostPos

	bool				IsCompress;								// enable compression

	u32					OutputThreadCnt;						// number of active threads
	OutputThread_t		OutputThread[256];						// thread specific data
	pthread_t   		PushThread[256];						// worker thread list

	volatile u32		CPUActiveCnt;							// total number of active cpus

	volatile u64		WorkerTSCTotal[256];					// total TSC 
	volatile u64		WorkerTSCTop[256];						// cycles used for acutal data processing 
	volatile u64		WorkerTSCCompress[256];					// cycles spent for compression 
	volatile u64		WorkerTSCSend[256];						// cycles spent for tcp sending 
	volatile u64		WorkerTSCRecv[256];						// cycles spent for tcp recv
	*/

} Output_t;

static void* Output_Worker(void * user);

//-------------------------------------------------------------------------------------------

extern bool 			g_Verbose;
//extern u32				g_ESTimeout;
//extern bool				g_Output_Keepalive;
//extern bool				g_Output_FilterPath;
//extern u32				g_Output_ThreadCnt;
//extern u32				g_Output_MergeMin;
//extern u32				g_Output_MergeMax;

static volatile bool	s_Exit 			= false;
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

	return O;
}

//-------------------------------------------------------------------------------------------

void Output_Close(Output_t* Out)
{
	fprintf(stderr, "Output close\n");

	// signal workers to revolt
	s_Exit = true;

	if (Out->FileTXT) fclose(Out->FileTXT);

	fprintf(stderr, "  Total Line : %lli\n", Out->TotalLine);
	fprintf(stderr, "  Total Byte : %lli\n", Out->TotalByte);
}

//-------------------------------------------------------------------------------------------

u64 Output_TotalByteSent(Output_t* Out)
{
	return Out->TotalByte;
}

//-------------------------------------------------------------------------------------------

u64 Output_TotalLine(Output_t* Out)
{
	return Out->TotalLine;
}

//-------------------------------------------------------------------------------------------

u64 Output_ESErrorCnt(Output_t* Out)
{
	/*
	u32 TotalError = 0; 
	for (int i=0; i < Out->CPUActiveCnt; i++)
	{
		TotalError += Out->ESPushError[i];
	}
	return TotalError; 
	*/
	return 0;
}

//-------------------------------------------------------------------------------------------

u64 Output_ESPushCnt(Output_t* Out)
{
	/*
	u32 TotalPush = 0; 
	for (int i=0; i < Out->CPUActiveCnt; i++)
	{
		TotalPush += Out->ESPushTotal[i];
	}
	return TotalPush; 
	*/
	return 0;
}

//-------------------------------------------------------------------------------------------

u64 Output_BufferAdd(Output_t* Out, u8* Buffer, u32 BufferLen, u32 LineCnt)
{
	// drop null buffers
	if (BufferLen == 0) return 0;

	// write to a text file
	if (Out->FileTXT)
	{
		fprintf(Out->FileTXT, Buffer);
	}

	// update total line stats
	__sync_fetch_and_add(&Out->TotalLine, LineCnt);

	// total bytes queued
	__sync_fetch_and_add(&Out->TotalByte, BufferLen);

	return 0;
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
	/*
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
	*/
}

//-------------------------------------------------------------------------------------------
// not perfectly correct... aka very non thread safe, but its just hisograms
// used for debuging / performance tuning
void Output_ESHisto(Output_t* Out)
{
	/*
	u32 HistoTx[1024];
	u32 HistoRx[1024];
	memset(HistoTx, 0, sizeof(HistoTx));
	memset(HistoRx, 0, sizeof(HistoRx));

	fprintf(stderr, "Output Histogram\n");	

	u32 HistoMax	= Out->OutputThread[0].ESHistoMax;
	u32 HistoBinTx	= Out->OutputThread[0].ESHistoBinTx;
	u32 HistoBinRx	= Out->OutputThread[0].ESHistoBinRx;

	for (int i=0; i < Out->OutputThreadCnt; i++)
	{
		OutputThread_t* T = &Out->OutputThread[i];
		for (int j=0; j < HistoMax; j++)
		{
			HistoTx[j] += T->ESHistoTx[j];
			HistoRx[j] += T->ESHistoRx[j];
		}
		// not thread safe but dont care
		memset(T->ESHistoTx, 0, sizeof(T->ESHistoTx) );
		memset(T->ESHistoRx, 0, sizeof(T->ESHistoRx) );
	}

	// calc max

	u32 HistoTxMax = 0;
	u32 HistoTxTotal = 0;

	u32 HistoRxMax = 0;
	u32 HistoRxTotal = 0;

	for (int i=0; i < HistoMax; i++)
	{
		HistoTxTotal 	+= HistoTx[i];
		HistoTxMax 		= max32(HistoTxMax, HistoTx[i]);

		HistoRxTotal 	+= HistoRx[i];
		HistoRxMax 		= max32(HistoRxMax, HistoRx[i]);
	}

	fprintf(stderr, "HistoTx Total: %i\n", HistoTxTotal);
	for (int i=0; i < HistoMax; i++)
	{
		if (HistoTx[i] == 0) continue;
		fprintf(stderr, "    %6.f msec : %5i | ", ((float)i * HistoBinTx) / 1e6, HistoTx[i]);  
		for (int j=0; j < (HistoTx[i] * 80) / HistoTxMax; j++) fprintf(stderr, "*");
		fprintf(stderr, "\n");
	}

	fprintf(stderr, "HistoRx Total: %i\n", HistoRxTotal);
	for (int i=0; i < HistoMax; i++)
	{
		if (HistoRx[i] == 0) continue;
		fprintf(stderr, "    %6.f msec : %5i | ", ((float)i * HistoBinRx) / 1e6, HistoRx[i]);  
		for (int j=0; j < (HistoRx[i] * 80) / HistoTxMax; j++) fprintf(stderr, "*");
		fprintf(stderr, "\n");
	}
	*/
}
