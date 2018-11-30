#ifndef __FMAD_COMMON_PROFILE_H__
#define __FMAD_COMMON_PROFILE_H__

extern u64 g_ProfileStart[32];
extern u64 g_ProfileStop[32];
extern u64 g_ProfileTotal[32];
extern char* g_ProfileDesc[32];

//---------------------------------------------------------------------------------------------

void fProfile_Reset(void);
void fProfile_Dump(u32 Index);

static inline void fProfile_Start(u32 Index, char* Desc)
{
	g_ProfileStart[Index] = rdtsc();
	g_ProfileDesc[Index] = Desc; 
}

static inline void fProfile_Stop(u32 Index)
{
	g_ProfileTotal[Index] += rdtsc() - g_ProfileStart[Index];
}

static inline u64 fProfile_Cycles(u32 Index)
{
	return g_ProfileTotal[Index];
}

//---------------------------------------------------------------------------------------------
// intel code analyzer

#if defined (__GNUC__)
#define IACA_SSC_MARK( MARK_ID )                        \
__asm__ __volatile__ (                                  \
                      "\n\t  movl $"#MARK_ID", %%ebx"   \
                      "\n\t  .byte 0x64, 0x67, 0x90"    \
                      : : : "memory" );

#define IACA_UD_BYTES __asm__ __volatile__ ("\n\t .byte 0x0F, 0x0B");

#define IACA_START {IACA_UD_BYTES     IACA_SSC_MARK(111)}
#define IACA_END {IACA_SSC_MARK(222)  IACA_UD_BYTES}

#endif


#endif
