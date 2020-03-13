//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The Creative Commons BY-NC 4.0 International License see LICENSE file for details 
// 
// Histogram generation from pcap
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <locale.h>
#include <linux/sched.h>
#include <pthread.h>

#include "fTypes.h"
#include "fProfile.h"
#include "histogram.h"

//---------------------------------------------------------------------------------------------

PacketInfoBulk_t* PktInfo_BulkAlloc(u32 MaxPkts)
{
	PacketInfoBulk_t *p = malloc(sizeof(PacketInfoBulk_t));

	assert(p != NULL);

	p->Max		= MaxPkts;
	p->Pos		= 0;
	p->PktInfo	= malloc(sizeof(PacketInfo_t) * p->Max);
	p->Next		= NULL;

	return p;
}

//---------------------------------------------------------------------------------------------

void PktInfo_Insert(PacketInfoBulk_t **pB, u16 Len, u64 Tdiff)
{
	if (*pB == NULL)
	{
		// allocate space for 1024 pkts histograms to avoid frequent malloc
		*pB = PktInfo_BulkAlloc(1024);
	}
	PacketInfoBulk_t *P = *pB;

	if (P->Max == P->Pos)
	{
		// adding the new allocated node to the start of the list
		PacketInfoBulk_t *P	= PktInfo_BulkAlloc(1024);
		P->Next	= *pB;
		*pB		= P;
	}

	// TS calculation:
	// HistogramDump_t  will have FirstTS
	// and each pkt will have TS diff wrt previous pkt.
	// If it's 1st pkt then TSDiff will be 0.
	// [Header] | [ pkt1 |  pkt2  |  pkt3  | ... | pktN       ]
	// [  TS  ] | [   0  |TS-p1_TS|TS-p2_TS| ... |TS-p(N-1)_TS]
	// NOTE: If TSDIff > 4.294 seconds then it  will be rounded off to ~4.294 seconds (u32 max limitation)
	if (Tdiff >= UINT32_MAX)
		(P->PktInfo + P->Pos)->TSDiff	= UINT32_MAX-1;
	else
		(P->PktInfo + P->Pos)->TSDiff	= (u32)Tdiff;
	(P->PktInfo + P->Pos)->PktSize	= Len;

	P->Pos++;
}

//---------------------------------------------------------------------------------------------

int PktInfo_HistogramPrint(FILE *FP, HistogramDump_t *HD, PacketInfoBulk_t *PktInfoB)
{
	static u32 count = 0;
	u8 *Buffer = malloc(sizeof(HistogramDump_t) + HD->TotalPkt*sizeof(PacketInfo_t) + 128);

	HistogramDump_t	*H = (HistogramDump_t *)Buffer;
	memcpy(H, HD, sizeof(HistogramDump_t));

	//fprintf(stderr, "Histogram: %6u %08x %08x %4d %llu %6llu\n", H->FlowID, H->MACProto, H->IPProto, H->IPDSCP, H->FirstTS, H->TotalPkt);
	PacketInfo_t	*PD = (PacketInfo_t*)(H+1);

	PacketInfoBulk_t *p = PktInfoB;
	for (; p; p=p->Next)
	{
		for (u32 i = 0; i < p->Pos; i++)
		{
			PD->TSDiff	= (p->PktInfo + i)->TSDiff;
			PD->PktSize	= (p->PktInfo + i)->PktSize;
			PD			= PD + 1;
			count++;
		}
	}
	fwrite(Buffer, (u8 *)PD - Buffer, 1, FP);
	//fprintf(stderr, "size: %ld count: %u\n", (u8 *)PD - Buffer, count);
	free(Buffer);
}

//---------------------------------------------------------------------------------------------
