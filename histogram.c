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


PacketInfoBulk_t* PktInfoBulk_Alloc(u32 MaxPkts)
{
	PacketInfoBulk_t *p = malloc(sizeof(PacketInfoBulk_t));

	assert(p != NULL);

	p->Max		= MaxPkts;
	p->Head		= 0;
	p->PktInfo	= malloc(sizeof(PacketInfo_t) * p->Max);
	p->Next		= NULL;

	return p;
}

void PktInfo_Insert(PacketInfoBulk_t *P, uint16_t Len, uint32_t Tdiff)
{
	assert(P != NULL);

	PacketInfoBulk_t *last = P;

	for (; last->Next != NULL; last = last->Next);

	if (last->Max == last->Head)
	{
		// allocate space for 1024 pkts histograms to avoid frequent malloc
		last->Next	= PktInfoBulk_Alloc(1024);
		last		= last->Next;
	}
	(last->PktInfo + last->Head)->TSDiff	= Tdiff;
	(last->PktInfo + last->Head)->PktSize	= Len;

	last->Head++;
}

int Histogram_Print(FILE *FP, HistogramDump_t *HD, PacketInfoBulk_t *PktInfoB)
{
	static u32 count = 0;
	u8 *Buffer = malloc(sizeof(HistogramDump_t) + HD->TotalPkt*sizeof(PacketInfo_t) + 128);

	HistogramDump_t	*H = (HistogramDump_t *)Buffer;
	memcpy(H, HD, sizeof(HistogramDump_t));
	//H->signature	= HISTOGRAM_SIG_V1;

	//fprintf(stderr, "Histogram: %u %d %d %d %llu %llu\n", H->FlowID, H->MACProto, H->IPProto, H->IPDSCP, H->FirstTS, H->TotalPkt);

	PacketInfo_t	*PD = (PacketInfo_t*)(H+1);

	PacketInfoBulk_t *p = PktInfoB;
	for (; p; p=p->Next)
	{
		for (u32 i = 0; i < p->Head; i++)
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
