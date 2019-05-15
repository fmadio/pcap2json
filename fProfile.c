//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015, fmad engineering llc 
//
// quick and dirty profiling 
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

#include "fTypes.h"
#include "fProfile.h"


u64 g_ProfileStart[32];
u64 g_ProfileStop[32];
u64 g_ProfileTotal[32];
char* g_ProfileDesc[32];

void fProfile_Reset(void)
{
	for (int i=0; i < 16; i++)
	{
		g_ProfileStart	[i] = 0;
		g_ProfileStop	[i] = 0;
		g_ProfileTotal	[i] = 0;
	}
}

void fProfile_Dump(u32 Index)
{
	double oot = 1.0 / g_ProfileTotal[Index];
	for (int i=0; i < 16; i++)
	{
		fprintf(stderr, "    [%2i] %016llx %20lli : (%.4f) : %s\n", 
				i,
				g_ProfileTotal[i],
				g_ProfileTotal[i],
				g_ProfileTotal[i] * oot,
				g_ProfileDesc[i]);
	}
	fProfile_Reset();
}
