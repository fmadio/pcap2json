//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
//
// pcap latency diff  
//
//---------------------------------------------------------------------------------------------

#ifndef __F_TYPES_H__
#define __F_TYPES_H__

#include <math.h>
#include <limits.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

typedef unsigned int		bool;
#define true				1
#define false				0

typedef unsigned char		u8;
typedef char				s8;

typedef unsigned short		u16;
typedef short				s16;

typedef unsigned int 		u32;
typedef int					s32;

typedef unsigned long long	u64;
typedef long long			s64;

#define k1E9 1000000000ULL

#define kKB(a) ( ((u64)a)*1024ULL)
#define kMB(a) ( ((u64)a)*1024ULL*1024ULL)
#define kGB(a) ( ((u64)a)*1024ULL*1024ULL*1024ULL)
#define kTB(a) ( ((u64)a)*1024ULL*1024ULL*1024ULL*1024ULL)

// time utils

typedef struct
{
	int		year;
	int		month;
	int		day;
	int		hour;
	int		sec;
	int		min;
} clock_date_t;

static clock_date_t  clock_date(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	struct tm* t = localtime(&tv.tv_sec);

	clock_date_t c; 

	c.year		= 1900 + t->tm_year;
	c.month		= 1 + t->tm_mon;
	c.day		= t->tm_mday;
	c.hour		= t->tm_hour;
	c.min		= t->tm_min;
	c.sec		= t->tm_sec;

	return c;
}

// 0 - Sunday
// 1 - Monday 
// ...
// http://en.wikipedia.org/wiki/Determination_of_the_day_of_the_week#Implementation-dependent_methods_of_Sakamoto.2C_Lachman.2C_Keith_and_Craver 
static inline int dayofweek(int d, int m, int y)
{
    static int t[] = { 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    y -= m < 3;
    return ( y + y/4 - y/100 + y/400 + t[m-1] + d) % 7;
}

// generates date in web format RFC1123
static inline void  clock_rfc1123(u8* Str, clock_date_t c)
{
	const char *DayStr[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char *MonthStr[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	struct tm t;
	t.tm_year		= c.year - 1900;
	t.tm_mon		= c.month - 1;
	t.tm_mday		= c.day;
	t.tm_hour		= c.hour;
	t.tm_min		= c.min;
	t.tm_sec		= c.sec;

	int wday		= dayofweek(c.day, c.month, c.year);

    const int RFC1123_TIME_LEN = 29;
	strftime(Str, RFC1123_TIME_LEN+1, "---, %d --- %Y %H:%M:%S GMT", &t);
	memcpy(Str, 	DayStr	[wday], 3);
    memcpy(Str+8, 	MonthStr[c.month - 1], 3);
}

static inline void  clock_str(u8* Str, clock_date_t c)
{
	sprintf(Str, "%04i%02i%02i_%02i-%02i-%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);
}
static inline void  ns_str(u8* Str, u64 NS) 
{
	u64 sec = NS % k1E9;	
	int msec = sec / 1000000ULL; 
	int usec = (sec - msec*1000000ULL)/ 1000ULL; 
	int nsec = (sec - msec*1000000ULL- usec*1000ULL);

	sprintf(Str, "%03i.%03i.%03i", msec, usec, nsec);
}

// epoch nanos -> year, mont, day, ..
static clock_date_t  ns2clock(u64 ts)
{
	time_t t0 = ts / 1e9;

	struct tm* t = localtime(&t0);
	clock_date_t c; 

	c.year		= 1900 + t->tm_year;
	c.month		= 1 + t->tm_mon;
	c.day		= t->tm_mday;
	c.hour		= t->tm_hour;
	c.min		= t->tm_min;
	c.sec		= t->tm_sec;

	return c;
}

// verbose -> nanos since epoch
static u64 clock2ns(int year, int month, int day, int hour, int min, int sec)
{
	struct tm t;

	t.tm_year 	= year - 1900;
	t.tm_mon	= month-1;
	t.tm_mday	= day;
	t.tm_hour	= hour;
	t.tm_min	= min;
	t.tm_sec	= sec;

	time_t epoch = mktime(&t);
	return (u64)epoch * (u64)1e9; 
}

static u64 clock_date2ns(clock_date_t d)
{
	struct tm t;

	t.tm_year 	= d.year - 1900;
	t.tm_mon	= d.month-1;
	t.tm_mday	= d.day;
	t.tm_hour	= d.hour;
	t.tm_min	= d.min;
	t.tm_sec	= d.sec;

	time_t epoch = mktime(&t);
	return (u64)epoch * (u64)1e9; 
}

// returns the first day of the week
static clock_date_t clock_startofweek(clock_date_t d)
{
	struct tm t;

	int wday		= dayofweek(d.day, d.month, d.year);

	t.tm_year 	= d.year - 1900;
	t.tm_mon	= d.month-1;
	t.tm_mday	= d.day - wday;
	t.tm_hour	= d.hour;
	t.tm_min	= d.min;
	t.tm_sec	= d.sec;

	mktime(&t);

	clock_date_t r;
	r.year		= 1900 + t.tm_year;
	r.month		= 1 + t.tm_mon;
	r.day		= t.tm_mday;
	r.hour		= t.tm_hour;
	r.min		= t.tm_min;
	r.sec		= t.tm_sec;

	return r;
}


// epoch in nanos 
static u64 clock_ns(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (u64)tv.tv_sec *(u64)1e9 +(u64)tv.tv_usec * (u64)1e3;
}

static inline volatile u64 rdtsc(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );
	return (((u64)hi)<<32ULL) | (u64)lo;
}

extern double TSC2Nano;
static inline volatile u64 rdtsc_ns(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );

	u64 ts = (((u64)hi)<<32ULL) | (u64)lo;
	return ts * TSC2Nano; 
}

static inline volatile u64 rdtsc2ns(u64 ts)
{
	return ts * TSC2Nano; 
}

static inline volatile u64 tsc2ns(u64 ts)
{
	return ts * TSC2Nano; 
}

static inline u64 ns2tsc(u64 ns)
{
	return (u64)( (double)ns / TSC2Nano);
}

static void ndelay(u64 ns)
{
	u64 NextTS = rdtsc() + ns2tsc(ns);
	while (rdtsc() < NextTS)
	{
		__asm__ volatile("pause");
		__asm__ volatile("pause");
		__asm__ volatile("pause");
		__asm__ volatile("pause");
	}
}

static inline void prefetchnta(void* ptr)
{
	__asm__ volatile("prefetchnta (%0)" :  : "r"(ptr));
}

static inline u32 swap32(const u32 a)
{
	return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

static inline u16 swap16(const u16 a)
{
	return (((a>>8)&0xFF)<<0) | (((a>>0)&0xFF)<<8);
}

static inline u64 swap64(const u64 a)
{
	return swap32(a>>32ULL) | ( (u64)swap32(a) << 32ULL); 
}

static inline u32 min32(const u32 a, const u32 b)
{
	return (a < b) ? a : b;
}

static inline s32 min32s(const s32 a, const s32 b)
{
	return (a < b) ? a : b;
}

static inline u32 max32(const u32 a, const u32 b)
{
	return (a > b) ? a : b;
}
static inline s32 max32s(const s32 a, const s32 b)
{
	return (a > b) ? a : b;
}


static inline s32 sign32(const s32 a)
{
	if (a == 0) return 0;
	return (a > 0) ? 1 : -1;
}

static inline u64 min64(const u64 a, const u64 b)
{
	return (a < b) ? a : b;
}

static inline u64 max64(const u64 a, const u64 b)
{
	return (a > b) ? a : b;
}

static inline double maxf(const double a, const double b)
{
	return (a > b) ? a : b;
}

static inline double minf(const double a, const double b)
{
	return (a < b) ? a : b;
}
static inline double clampf(const double min, const double v, const double max)
{
	return maxf(min, minf(v,  max)); 
}

static inline double inverse(const double a)
{
	if (a == 0) return 0;
	return 1.0 / a;
}

static inline double fSqrt(const double a)
{
	if (a <= 0) return 0;
	return sqrtf(a);
}

static inline double signf(const double a)
{
	if (a > 0) return  1.0;
	if (a < 0) return -1.0;

	// keep it simple..
	return 1;
}

static inline double alog(const double a)
{
	if (a == 0) return 0;
	if (a < 0) return -logf(-a);
	return -logf(a);
}

static inline char* FormatTS(u64 ts)
{
	u64 usec = ts / 1000ULL;
	u64 msec = usec / 1000ULL;
	u64 sec = msec / 1000ULL;
	u64 min = sec / 60ULL;
	u64 hour = min / 60ULL;

	u64 nsec = ts - usec*1000ULL;
	usec = usec - msec*1000ULL;
	msec = msec - sec*1000ULL;
	sec = sec - min*60ULL;
	min = min - hour*60ULL;

	static char List[16][128];
	static int Pos = 0;

	char* S = List[Pos];
	Pos = (Pos + 1) & 0xf;

	sprintf(S, "%02lli:%02lli:%02lli.%03lli.%03lli.%03lli", hour % 24, min, sec, msec,usec, nsec);

	return S;
}

static inline void CycleCalibration(void)
{
    fprintf(stderr, "calibrating...\n");
    u64 StartTS[16];
    u64 EndTS[16];

    u64 CyclesSum   = 0;
    u64 CyclesSum2  = 0;
    u64 CyclesCnt   = 0;
    for (int i=0; i < 1; i++)
    {
        u64 NextTS = clock_ns() + 1e9;
        u64 StartTS = rdtsc();
        while (clock_ns() < NextTS)
        {
        }
        u64 EndTS  = rdtsc();

        u64 Cycles = EndTS - StartTS;
        CyclesSum += Cycles;
        CyclesSum2 += Cycles*Cycles;
        CyclesCnt++;

        fprintf(stderr, "%i : %016llx %16.4f cycles/nsec\n", i, Cycles, Cycles / 1e9);
    }

    double CyclesSec = CyclesSum / CyclesCnt;
    double CyclesStd = sqrt(CyclesCnt *CyclesSum2 - CyclesSum *CyclesSum) / CyclesCnt;
    fprintf(stderr, "Cycles/Sec %12.4f Std:%8.fcycle std(%12.8f)\n", CyclesSec, CyclesStd, CyclesStd / CyclesSec);

	// set global

	TSC2Nano = 1e9 / CyclesSec;
}
// convert pcap style sec : nsec format into pure nano
static inline u64 nsec2ts(u32 sec, u32 nsec)
{
	return (u64)sec * 1000000000ULL + (u64)nsec;
}

// ethernet header
typedef struct
{
	u8		Dst[6];
	u8		Src[6];
	u16		Proto;

} __attribute__((packed)) fEther_t;

#define ETHER_PROTO_IPV4		0x0800 
typedef struct
{
	union
	{
		u32		IP4;	
		u8		IP[4];
	};

} IP4_t;

typedef struct
{
	u8		Version;
	u8		Service;
	u16		Len;
	u16		Ident;
	u16		Frag;
	u8		TTL;
	u8		Proto;
	u16		CSum;

	IP4_t	Src;
	IP4_t	Dst;

} __attribute__((packed)) IP4Header_t;

#define IPv4_PROTO_TCP			6
#define IPv4_PROTO_UDP			17	

#define TCP_FLAG_SYN(a) ((a >>(8+1))&1)
#define TCP_FLAG_ACK(a) ((a >>(8+4))&1)
#define TCP_FLAG_FIN(a) ((a >>(8+0))&1)

typedef struct
{
	u16			PortSrc;
	u16			PortDst;
	u32			SeqNo;
	u32			AckNo;
	u16			Flags;
	u16			Window;
	u16			CSUM;
	u16			Urgent;

} __attribute__((packed)) TCPHeader_t;

typedef struct
{
	u16			PortSrc;
	u16			PortDst;
	u16			Length;
	u16			CSUM;

} __attribute__((packed)) UDPHeader_t;

// pcap headers

#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
#define PCAPHEADER_MAJOR			2
#define PCAPHEADER_MINOR			4
#define PCAPHEADER_LINK_ETHERNET	1

typedef struct
{
	u32				Sec;				// time stamp sec since epoch 
	u32				NSec;				// nsec fraction since epoch

	u32				LengthCapture;		// captured length, inc trailing / aligned data
	u32				LengthWire;			// length on the wire

} __attribute__((packed)) PCAPPacket_t;

// per file header

typedef struct
{
	u32				Magic;
	u16				Major;
	u16				Minor;
	u32				TimeZone;
	u32				SigFlag;
	u32				SnapLen;
	u32				Link;

} __attribute__((packed)) PCAPHeader_t;

#endif
