//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018 fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
// 
// PCAP to JSON file conversion. convers a PCAP and extracts basic IP / TCP / UDP information
// that can be fed into Elastic Search for further processing and analysis 
//
// PCAP format (2018/12/27)
//
// 64B line rate 2 x 10Gbps
// [05:54:55.555.243.408] In:12.000 GB 2.68 Mpps 1.37 Gbps PCAP:  14.88 Gbps | Out 0.00000 GB Flows/Snap:      0 FlowCPU:0.00 | ESPush:     0   0.00K ESErr    0 | OutCPU: 0.00 (0.00)
// [05:54:55.647.520.418] In:12.160 GB 2.68 Mpps 1.37 Gbps PCAP:  14.88 Gbps | Out 0.00000 GB Flows/Snap:      0 FlowCPU:0.00 | ESPush:     0   0.00K ESErr    0 | OutCPU: 0.00 (0.00)
// [05:54:55.739.617.444] In:12.319 GB 2.68 Mpps 1.37 Gbps PCAP:  14.88 Gbps | Out 0.00000 GB Flows/Snap:      0 FlowCPU:0.00 | ESPush:     0   0.00K ESErr    0 | OutCPU: 0.00 (0.00)
//
// FMAD chunked format (2018/12/28)
//
// es-stdout > /dev/null
//
// [05:54:51.333.710.607] In:4.685 GB 10.79 Mpps 5.52 Gbps PCAP:  14.88 Gbps | Out 0.00002 GB Flows/Snap:      2 FlowCPU:1.00 | ESPush:     0   0.01K ESErr    0 | OutCPU: 0.00 (0.00)
// [05:54:51.704.135.799] In:5.327 GB 10.77 Mpps 5.51 Gbps PCAP:  14.88 Gbps | Out 0.00002 GB Flows/Snap:      2 FlowCPU:1.00 | ESPush:     0   0.01K ESErr    0 | OutCPU: 0.00 (0.00)
// [05:54:52.073.885.145] In:5.968 GB 10.75 Mpps 5.50 Gbps PCAP:  14.88 Gbps | Out 0.00002 GB Flows/Snap:      2 FlowCPU:1.00 | ESPush:     0   0.01K ESErr    0 | OutCPU: 0.00 (0.00)
// [05:54:52.445.099.551] In:6.611 GB 10.79 Mpps 5.52 Gbps PCAP:  14.88 Gbps | Out 0.00003 GB Flows/Snap:      2 FlowCPU:1.00 | ESPush:     0   0.01K ESErr    0 | OutCPU: 0.00 (0.00)
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

#include "fTypes.h"
#include "fProfile.h"
#include "output.h"
#include "flow.h"

double TSC2Nano = 0;

typedef struct
{
	u8						HostName[256];		// ES Host name
	u32						HostPort;			// ES Port name

} ESHost_t;

#define OUTPUT_VERSION_1_00		0x100		// initial version
typedef struct
{
	u64				Version;				// version of output ring 	
	u64				ChunkSize;				// size in bytes of each chunk
	u64				pad0[16 - 2];			// header pad


	volatile u64	Put;					// location of writer 
	volatile u64	Get;					// location of reader 
	u64				Mask;					// mask of buffer
	u64				Max;					// mask of buffer
	volatile u64	End;					// end of the capture stream

	u64				pad2[16 - 5];

} OutputHeader_t;


//---------------------------------------------------------------------------------------------
// tunables
bool			g_Verbose			= false;				// verbose print mode
s32				g_CPUCore[2]		= {14, 12};					// which CPU to run the main flow logic on
s32				g_CPUFlow[16]		= { 19, 20, 21, 22};	// cpu mapping for flow threads
s32				g_CPUOutput[16]		= { 25, 26, 27, 28, 25, 26, 27, 28};	// cpu mappings for output threads 

bool			g_IsJSONPacket		= false;			// output JSON packet format
bool			g_IsJSONFlow		= false;			// output JSON flow format

s64				g_FlowSampleRate	= 100e6;			// default to flow sample rate of 100msec
bool			g_IsFlowNULL		= false;			// benchmarking NULL flow rate 
u32				g_FlowIndexDepth	= 6;				// number of parallel flow index structures to allocate
														// ideally should == flow CPU count
u64				g_FlowMax			= 250e3;			// maximum number of flows per snapshot
bool			g_FlowTopNEnable	= false;			// enable or disable output the top N flows
u32				g_FlowTopNMax		= 1000;				// number of top flow to output
u8				g_FlowTopNMac		= 0;				// count of topN flows for particuar MAC address
u8				g_FlowTopNsMac[MAX_TOPN_MAC][6];				// topN source MAC
u8				g_FlowTopNdMac[MAX_TOPN_MAC][6];				// topN destination MAC

bool			g_Output_NULL		= false;			// benchmarking mode output to /dev/null 
bool			g_Output_STDOUT		= true;				// by default output to stdout 
bool			g_Output_ESPush		= false;			// direct ES HTTP Push 
u32				g_Output_BufferCnt	= 64;				// number of output buffers

u32				g_ESHostCnt 		= 0;				// number of active ES Hosts
ESHost_t		g_ESHost[128];							// list fo ES Hosts to output to
bool			g_ESCompress		= false;			// elastic push enable compression 
bool			g_ESNULL			= false;			// ues ES NULL Host 
u8*				g_ESQueuePath		= NULL;				// if using file backed ES Queue

u8 				g_CaptureName[256];						// name of the capture / index to push to
u8				g_DeviceName[128];						// name of the device this is sourced from

u64				s_TotalPkt			= 0;				// total packets processed
u64				s_TotalByteCapture	= 0;				// total bytes captured 
u64				s_TotalByteWire		= 0;				// total bytes on the wire incomming 

u64				s_StreamCAT_BytePending = 0;			// number of bytes pending in stream cat
float			s_StreamCAT_CPUActive 	= 0;			// stream_cat cpu active pct
float			s_StreamCAT_CPUFetch 	= 0;			// stream_cat cpu fetch from stroage utilization 
float			s_StreamCAT_CPUSend 	= 0;			// stream_cat cpu send down pipe utilization 

//---------------------------------------------------------------------------------------------


static void* Push_Worker(void* _User);

//---------------------------------------------------------------------------------------------

static void help(void)
{
	fprintf(stderr, "fmad engineering all rights reserved\n");
	fprintf(stderr, "http://www.fmad.io\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "pcap2json is a high speed PCAP meta data extraction utility\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "example converting a pcap to json:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "cat /tmp/test.pcap | pcap2json > test.json\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Command Line Arguments:\n");
	fprintf(stderr, " --index-name <name>          : capture name to use for ES Index data\n");
	fprintf(stderr, " --verbose                      : verbose output\n");
	fprintf(stderr, " --config <confrig file>        : read from config file\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " --cpu-core   <cpu no>          : cpu map for core thread\n"); 
	fprintf(stderr, " --cpu-flow   <cpu0.. cpu3>     : cpu map for flow threads\n"); 
	fprintf(stderr, " --cpu-output <cpu0 .. cpu3>    : cpu map for output threads\n"); 
	fprintf(stderr, "\n");
	fprintf(stderr, " --json-packet                  : write JSON packet data\n");
	fprintf(stderr, " --json-flow                    : write JSON flow data\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "Output Mode\n");
	fprintf(stderr, " --output-stdout                : writes output to STDOUT\n");
	fprintf(stderr, " --output-espush                : writes output directly to ES HTTP POST \n");
	fprintf(stderr, " --output-buffercnt <pow2 cnt>  : number of output buffers (default is 64)\n");

	fprintf(stderr, "\n");
	fprintf(stderr, "Flow specific options\n");
	fprintf(stderr, " --flow-samplerate <nanos>      : scientific notation flow sample rate. default 100e6 (100msec)\n");
	fprintf(stderr, " --flow-index-depth <number>    : number of root flow index to allocate defulat 6\n");
	fprintf(stderr, " --flow-max   <number>          : maximum number of flows (default 250e3)6\n");
	fprintf(stderr, " --flow-top-n <number>          : only output the top N flows\n"); 
	fprintf(stderr, " --flow-top-n-circuit <sMAC_dMAC> : output top N flows based on specified src/dest MAC\n"); 

	fprintf(stderr, "\n");
	fprintf(stderr, "Elastic Stack options\n");
	fprintf(stderr, " --es-host <hostname:port>      : Sets the ES Hostname\n");
	fprintf(stderr, " --es-compress                  : enables gzip compressed POST\n");
	fprintf(stderr, " --es-null                      : use ES Null target for perf testing\n");
	fprintf(stderr, " --es-queue-path                : ES Output queue is file backed\n");
}

//---------------------------------------------------------------------------------------------

static bool ParseCommandLine(u8* argv[])
{
	u32 cnt = 0;
	if (strcmp(argv[0], "-v") == 0)
	{
		g_Verbose = true;
		cnt	+= 1;
	}
	// CPU for main process to run on 
	if (strcmp(argv[0], "--cpu-core") == 0)
	{
		g_CPUCore[0] = atoi(argv[1]);
		fprintf(stderr, "  Core on CPU %i\n", g_CPUCore[0]);
		cnt	+= 2;
	}
	if (strcmp(argv[0], "--cpu-flow") == 0)
	{
		g_CPUFlow[0] = atoi(argv[1]);
		g_CPUFlow[1] = atoi(argv[2]);
		g_CPUFlow[2] = atoi(argv[3]);
		g_CPUFlow[3] = atoi(argv[4]);

		g_CPUFlow[4] = atoi(argv[5]);
		g_CPUFlow[5] = atoi(argv[6]);
		g_CPUFlow[6] = atoi(argv[7]);
		g_CPUFlow[7] = atoi(argv[8]);

		fprintf(stderr, "  Flow on CPU %i %i %i %i  %i %i %i %i\n", g_CPUFlow[0], g_CPUFlow[1], g_CPUFlow[2], g_CPUFlow[3], g_CPUFlow[4], g_CPUFlow[5], g_CPUFlow[6], g_CPUFlow[7]);
		cnt	+= 8 + 1;
	}
	if (strcmp(argv[0], "--cpu-output") == 0)
	{
		g_CPUOutput[0] = atoi(argv[1]);
		g_CPUOutput[1] = atoi(argv[2]);
		g_CPUOutput[2] = atoi(argv[3]);
		g_CPUOutput[3] = atoi(argv[4]);
		fprintf(stderr, "  Output on CPU %i %i %i %i\n", 
							g_CPUOutput[0], g_CPUOutput[1], g_CPUOutput[2], g_CPUOutput[3] );
		cnt	+= 4 + 1;
	}
	// output json packet data 
	if (strcmp(argv[0], "--json-packet") == 0)
	{
		fprintf(stderr, "  Write JSON Packet meta data\n");
		g_IsJSONPacket = true;	
		cnt	+= 1;
	}
	// output json flow data 
	if (strcmp(argv[0], "--json-flow") == 0)
	{
		fprintf(stderr, "  Write JSON Flow meta data\n");
		g_IsJSONFlow = true;	
		cnt	+= 1;
	}
	// capture name 
	if (strcmp(argv[0], "--index-name") == 0)
	{
		strncpy(g_CaptureName, argv[1], sizeof(g_CaptureName));	
		fprintf(stderr, "  Capture Name[%s]\n", g_CaptureName);
		cnt	+= 2;
	}
	// benchmarking write to /dev/null 
	if (strcmp(argv[0], "--output-null") == 0)
	{
		g_Output_NULL 	= true;
		g_Output_ESPush = false;
		fprintf(stderr, "  Output to NULL\n");
		cnt	+= 1;
	}
	// default output to stdout
	if (strcmp(argv[0], "--output-stdout") == 0)
	{
		g_Output_NULL 	= false;
		g_Output_STDOUT = true;
		g_Output_ESPush = false;
		fprintf(stderr, "  Output to STDOUT\n");
		cnt	+= 1;
	}
	if (strcmp(argv[0], "--output-espush") == 0)
	{
		g_Output_NULL 	= false;
		g_Output_STDOUT = false;
		g_Output_ESPush = true;
		fprintf(stderr, "  Output to ES HTTP Push\n");
		cnt	+= 1;
	}
	if (strcmp(argv[0], "--output-buffercnt") == 0)
	{
		g_Output_BufferCnt = atoi(argv[1]);
		if (g_Output_BufferCnt & (g_Output_BufferCnt  -1))
		{
			fprintf(stderr, "  Output Buffer Cnt must be Power of 2: %i\n", g_Output_BufferCnt);
			return false;
		}
		if (g_Output_BufferCnt > 16*1024)
		{
			fprintf(stderr, "  Output Buffer Cnt maximum of 16384: %i\n", g_Output_BufferCnt);
			return false;
		}

		fprintf(stderr, "  Output Buffer Cnt: %i\n", g_Output_BufferCnt);
		cnt	+= 2;
	}

	// ES specific 
	if (strcmp(argv[0], "--es-host") == 0)
	{
		// split into host/port from <hostname:port>
		u32 StrPos = 0;
		u8 StrList[2][256];
		u32 Len = 0;

		u8* HostPort = argv[1];
		for (int j=0; j < strlen(HostPort); j++)
		{
			u32 c = HostPort[j];	
			if ((c == ':') || (c == 0))
			{
				StrList[StrPos][Len] = 0;
				StrPos++;
				Len = 0;
			}
			else
			{
				StrList[StrPos][Len++] = c;
			}
		}
		StrList[StrPos][Len] = 0;
		StrPos++;

		if (StrPos != 2)
		{
			fprintf(stderr, "  Format incorrect\n--es-host <hostname:port> found %i\n", StrPos);
			return false;
		}

		ESHost_t* Host = &g_ESHost[g_ESHostCnt++];

		strncpy(Host->HostName, StrList[0], sizeof(Host->HostName));
		Host->HostPort = atoi(StrList[1]);
		fprintf(stderr, "  ES[%i] HostName [%s]  HostPort:%i\n", g_ESHostCnt, Host->HostName, Host->HostPort);
		cnt	+= 2;
	}
	if (strcmp(argv[0], "--es-compress") == 0)
	{
		g_ESCompress = true;
		fprintf(stderr, "  ES Compression Enabled\n");
		cnt	+= 1;
	}
	if (strcmp(argv[0], "--es-null") == 0)
	{
		g_ESNULL = true;
		fprintf(stderr, "  ES NULL Target\n");
		cnt	+= 1;
	}
	if (strcmp(argv[0], "--es-queue-path") == 0)
	{
		g_ESQueuePath = strdup(argv[1]);
		fprintf(stderr, "  ES Queue Path [%s]\n", g_ESQueuePath);
		cnt	+= 2;
	}

	// flow specific
	if (strcmp(argv[0], "--flow-samplerate") == 0)
	{
		g_FlowSampleRate = atof(argv[1]);
		fprintf(stderr, "  Flow Sample rate %.3f msec\n", g_FlowSampleRate / 1e6);
		cnt	+= 2;
	}
	// number of parallel structures. ideally same as flow CPU count 
	if (strcmp(argv[0], "--flow-index-depth") == 0)
	{
		g_FlowIndexDepth = atoi(argv[1]);
		fprintf(stderr, "  Flow Index Depth:%i\n", g_FlowIndexDepth);
		cnt	+= 2;
	}
	// maximum flow count 
	if (strcmp(argv[0], "--flow-max") == 0)
	{
		g_FlowMax = atof(argv[1]);
		fprintf(stderr, "  Flow Maximum Count:%lli\n", g_FlowMax);
		cnt	+= 2;
	}
	// output top-N talkers 
	if (strcmp(argv[0], "--flow-top-n") == 0)
	{
		g_FlowTopNEnable	= true;
		g_FlowTopNMax 		= atof(argv[1]);
		fprintf(stderr, "  Flow Top-N max:%i\n", g_FlowTopNMax);
		cnt	+= 2;
	}
	// output top-N based on source/destination MAC
	if (strcmp(argv[0], "--flow-top-n-circuit") == 0)
	{
		if (g_FlowTopNMac == MAX_TOPN_MAC)
		{
			fprintf(stderr, "  Error: max --flow-top-n-circuit limit(%d) reached !\n", MAX_TOPN_MAC);
		}
		else
		{
			int ret = sscanf(argv[1], MAC_FMT"_"MAC_FMT,
					&g_FlowTopNsMac[g_FlowTopNMac][0], &g_FlowTopNsMac[g_FlowTopNMac][1], &g_FlowTopNsMac[g_FlowTopNMac][2],
					&g_FlowTopNsMac[g_FlowTopNMac][3], &g_FlowTopNsMac[g_FlowTopNMac][4], &g_FlowTopNsMac[g_FlowTopNMac][5],
					&g_FlowTopNdMac[g_FlowTopNMac][0], &g_FlowTopNdMac[g_FlowTopNMac][1], &g_FlowTopNdMac[g_FlowTopNMac][2],
					&g_FlowTopNdMac[g_FlowTopNMac][3], &g_FlowTopNdMac[g_FlowTopNMac][4], &g_FlowTopNdMac[g_FlowTopNMac][5]);
			if (ret == 12)
			{
				fprintf(stderr, "  g_FlowTopNMac: %d\n"\
								"  src mac: " MAC_FMT "\n"\
								"  dst mac: " MAC_FMT "\n",
					g_FlowTopNMac+1, MAC_PRINT(g_FlowTopNsMac[g_FlowTopNMac]), MAC_PRINT(g_FlowTopNdMac[g_FlowTopNMac]));
				g_FlowTopNMac++;
			}
			else
			{
				fprintf(stderr, "  Error while parsing \"--flow-top-n-circuit SMAC_DMAC\" config option\n");
			}
		}
		cnt	+= 2;
	}
	// flow null 
	if (strcmp(argv[0], "--flow-null") == 0)
	{
		g_IsFlowNULL = true; 
		fprintf(stderr, "  Flow NULL benchmarking\n"); 
		cnt	+= 1;
	}

	// create a unique id so calling applications
	// can identify it with ps 
	if (strcmp(argv[0], "--uid") == 0)
	{
		u8* uid = argv[1];
		fprintf(stderr, "  UID [%s]\n", uid); 
		cnt	+= 2;
	}

	// allow custom device name
	if (strcmp(argv[0], "--device-name") == 0)
	{
		u8* Name = argv[1];
		strncpy(g_DeviceName, Name, sizeof(g_DeviceName));
		fprintf(stderr, "  Device Name [%s]\n", Name);
		cnt     += 2;
	}

	if (strcmp(argv[0], "--help") == 0)
	{
		help();
		return false;
	}

	// unknown command
	if (cnt == 0)
	{
		fprintf(stderr, "  Unknown command line option [%s]\n", argv[0]);
		return 0;
	}

	return cnt;
}

//---------------------------------------------------------------------------------------------
// read command line opts from file
static bool ParseConfigFile(u8* ConfigFile)
{
	fprintf(stderr, "Config File [%s]\n", ConfigFile);	

	FILE* F = fopen(ConfigFile, "r");
	if (!F)
	{
		fprintf(stderr, "unable to open config file [%s]\n", ConfigFile);
		return 0;
	}

	u32 LinePos = 0;
	u32 LineListPos = 0;
	u8* LineList[256];
	u8  LineBuffer[256];
	bool IsComment = false;
	while (!feof(F))
	{
		u32 c = fgetc(F);

		// wait for comment to complete
		if (IsComment)
		{
			if (c == '\n')
			{
				IsComment = false;
			}
		}
		else
		{
			switch (c)
			{
			case '\n':
			case ' ':
				{
					// remove any trailing whitespace
					// easy to copy the cmdline args + paste it into a config file
					for (int k=LinePos-1;  k > 0; k--)
					{
						if (LineBuffer[k] == ' ') LineBuffer[k] = 0;
						else break;
					}
					LineBuffer[LinePos++] = 0;		// asciiz

					if (LinePos > 1)
					{
						LineList[LineListPos] = strdup(LineBuffer);
						LineListPos += 1;
					}
					LinePos		=  0;
				}
				break;

			// argument encased in "" 
			case '"':
				{
					// consume line buffer until matching "
					while (!feof(F))
					{
						c = fgetc(F);
						if (c == '"') break;

						LineBuffer[LinePos++] = c;
					}
				}
				break;

			// comments
			case '#':
				IsComment = true;
				break;

			default:
				LineBuffer[LinePos++] = c;
				break;
			}
		}
	}
	fclose(F);

	// parse each command
	for (int j=0; j < LineListPos; j++)
	{
		fprintf(stderr, "[%s]\n", LineList[j]);	

		u32 inc = ParseCommandLine(&LineList[j]);
		if (inc == 0) return false;

		j += (inc - 1);
	}

	return true;
}

//---------------------------------------------------------------------------------------------
// dump performance stats
static void ProfileDump(struct Output_t* Out)
{
	fProfile_Dump(0);
	fprintf(stderr, "\n");

	float OutputWorkerCPU;
	float OutputWorkerCPUCompress;
	float OutputWorkerCPUSend;
	float OutputWorkerCPURecv;
	u64   OutputTotalCycle;
	u64   OutputPendingByte;
	u64   OutputPushSizeByte;
	Output_Stats(Out, 1,  	&OutputWorkerCPU, 
							&OutputWorkerCPUCompress, 
							&OutputWorkerCPUSend, 
							&OutputWorkerCPURecv,
							&OutputTotalCycle,
							&OutputPendingByte,
							&OutputPushSizeByte);

	fprintf(stderr, "Output Worker CPU\n");
	fprintf(stderr, "  Top      : %.6f\n", OutputWorkerCPU);
	fprintf(stderr, "  Compress : %.6f\n", OutputWorkerCPUCompress);
	fprintf(stderr, "  Send     : %.6f\n", OutputWorkerCPUSend);
	fprintf(stderr, "  Recv     : %.6f\n", OutputWorkerCPURecv);
	fprintf(stderr, "  Total    : %.6f sec\n", tsc2ns(OutputTotalCycle)/1e9 );
	fprintf(stderr, "  Pending  : %.6f MB\n", OutputPendingByte  / (float)kMB(1)); 
	fprintf(stderr, "  PushSize : %.2f MB\n", OutputPushSizeByte / (float)kMB(1)); 
	fprintf(stderr, "\n");

	u64 FlowCntSnapshot		= 0;
	u64 PktCntSnapshot 		= 0;
	u64 FlowCntTotal 		= 0;
	float FlowCPUDecode 	= 0;
	float FlowCPUHash 		= 0;
	float FlowCPUOutput 	= 0;
	float FlowCPUOStall 	= 0;
	float FlowCPUMerge 		= 0;
	float FlowCPUWrite 		= 0;
	float FlowCPUReset 		= 0;
	float FlowCPUWorker 	= 0;

	Flow_Stats( true, 
				&FlowCntSnapshot, 
				&PktCntSnapshot, 
				&FlowCntTotal, 
				&FlowCPUDecode, 
				&FlowCPUHash, 
				&FlowCPUOutput, 
				&FlowCPUOStall,
				&FlowCPUMerge,
				&FlowCPUWrite,
				&FlowCPUReset,
				&FlowCPUWorker);

	fprintf(stderr, "Flow:\n");
	fprintf(stderr, "  Process   : %.3f\n", FlowCPUDecode);
	fprintf(stderr, "  Hash      : %.3f\n", FlowCPUHash);
	fprintf(stderr, "  Output    : %.3f\n", FlowCPUOutput);
	fprintf(stderr, "  Merge     : %.3f\n", FlowCPUMerge);
	fprintf(stderr, "  Write     : %.3f\n", FlowCPUWrite);
	fprintf(stderr, "  OStall    : %.3f\n", FlowCPUOStall);
	fprintf(stderr, "  Reset     : %.3f\n", FlowCPUReset);
	fprintf(stderr, "  WrkStall  : %.3f\n", FlowCPUWorker);
	fprintf(stderr, "\n");

	fprintf(stderr, "  Flow/Snap : %-12lli\n", FlowCntSnapshot);
	fprintf(stderr, "  Pkts/Snap : %-12lli\n", PktCntSnapshot);
	fprintf(stderr, "\n");

	fprintf(stderr, "Flows      : %-lli\n", FlowCntTotal);
	fprintf(stderr, "Pkts       : %-lli\n", s_TotalPkt);
	fprintf(stderr, "Pkts/Flow  : %.3f\n", s_TotalPkt * inverse(FlowCntTotal));
	fprintf(stderr, "\n");

	fprintf(stderr, "StreamCat:\n");
	fprintf(stderr, "  Active   : %.3f\n", s_StreamCAT_CPUActive);
	fprintf(stderr, "  Fetch    : %.3f\n", s_StreamCAT_CPUFetch);
	fprintf(stderr, "  Send     : %.3f\n", s_StreamCAT_CPUSend);
	fprintf(stderr, "  Pending  : %.2f MB\n", s_StreamCAT_BytePending / (float)kMB(1) );

	// packet size histogram
	Flow_PktSizeHisto();

	fflush(stdout);
	fflush(stderr);
}

//---------------------------------------------------------------------------------------------

int main(int argc, u8* argv[])
{
	fprintf(stderr, "pcap2json https://www.github/fmadio/pcap2json build:%s %s\n", __DATE__, __TIME__);

	// get the hosts name
	gethostname(g_DeviceName, sizeof(g_DeviceName));	

	u8 ClockStr[128];
	clock_str(ClockStr, clock_date() );

	sprintf(g_CaptureName, "%s_%s", g_DeviceName, ClockStr); 
	for (int i=1; i < argc; i++)
	{
		// config file was specified 
		if (strcmp(argv[i], "--config") == 0)
		{
			if (!ParseConfigFile(argv[i+1])) return 0;
			i += 1;
		}
		else
		{
			fprintf(stderr, "[%s]\n", argv[i]); 

			u32 inc = ParseCommandLine(&argv[i]);
			if (inc == 0) return 0;

			i += (inc - 1);
		}
	}

	u64 TS0 = clock_ns();

	// print cpu mapping
	fprintf(stderr, "CPU Mapping\n");
	fprintf(stderr, "  Core   %i %i\n", g_CPUCore[0], g_CPUCore[1]);
	fprintf(stderr, "  Flow   %i %i %i %i %i %i %i %i\n", g_CPUFlow[0], g_CPUFlow[1], g_CPUFlow[2], g_CPUFlow[3], g_CPUFlow[4], g_CPUFlow[5], g_CPUFlow[6], g_CPUFlow[7]);
	fprintf(stderr, "  Output %i %i %i %i\n", g_CPUOutput[0], g_CPUOutput[1], g_CPUOutput[2], g_CPUOutput[3]);

	// set cpu affinity
	if (g_CPUCore[0] >= 0) 
	{
		cpu_set_t Thread0CPU;
		CPU_ZERO(&Thread0CPU);
		CPU_SET (g_CPUCore[0], &Thread0CPU);
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &Thread0CPU);
	}
	CycleCalibration();

	FILE* FileIn 	= stdin;
	FILE* FileOut 	= stdout;

	// read header
	PCAPHeader_t HeaderMaster;
	int rlen = fread(&HeaderMaster, 1, sizeof(HeaderMaster), FileIn);
	if (rlen != sizeof(HeaderMaster))
	{
		fprintf(stderr, "Failed to read pcap header\n");
		return 0;
	}

	// work out the input file format
	bool IsPCAP 	= false;
	bool IsFMAD 	= false;
	bool IsFMADRING = false;
	u64 TScale = 0;

	switch (HeaderMaster.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: 
		fprintf(stderr, "PCAP Nano\n"); 
		TScale = 1;    
		IsPCAP = true;
		break;
	case PCAPHEADER_MAGIC_USEC: 
		fprintf(stderr, "PCAP Micro\n");
		TScale = 1000; 
		IsPCAP = true;
		break;

	case PCAPHEADER_MAGIC_FMAD: 
		fprintf(stderr, "FMAD Format Chunked\n");
		TScale = 1; 
		IsFMAD = true;
		break;

	case PCAPHEADER_MAGIC_FMADRING: 
		fprintf(stderr, "FMAD Ringbuffer Chunked\n");
		TScale = 1; 
		IsFMADRING = true;
		break;


	default:
		fprintf(stderr, "invaliid PCAP format %08x\n", HeaderMaster.Magic);
		return -1;
	}

	u64 NextPrintTS		= 0;

	u64 PrintNextTSC	= 0;
	u64 ProfileNextTSC	= 0;
	u64 StartTSC		= rdtsc();
	u64 LastTSC			= rdtsc();
	u64 LastTS			= 0;

	// SHM ring format
	OutputHeader_t* SHMRingHeader	= NULL; 
	u8* SHMRingData					= NULL; 
	if (IsFMADRING)
	{
		// stream cat sends the size of the shm file
		u64 SHMRingSize = 0;
		fread(&SHMRingSize, 1, sizeof(SHMRingSize), FileIn);

		u8 SHMRingName0[128];			// stream_cat sends ring names in 128B
		u8 SHMRingName1[128];			// stream_cat sends ring names in 128B
		u8 SHMRingName2[128];			// stream_cat sends ring names in 128B
		u8 SHMRingName3[128];			// stream_cat sends ring names in 128B

		fread(SHMRingName0, 1, 128, FileIn);
		fread(SHMRingName1, 1, 128, FileIn);
		fread(SHMRingName2, 1, 128, FileIn);
		fread(SHMRingName3, 1, 128, FileIn);

		fprintf(stderr, "SHMRingName [%s] %lli\n", SHMRingName0, SHMRingSize);

		// open the shm ring
		int fd = shm_open(SHMRingName0, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
		if (fd < 0)
		{
			fprintf(stderr, "failed to create SHM ring buffer\n");
			return;
		}

		// map
		void* SHMMap = mmap(NULL, SHMRingSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (SHMMap == MAP_FAILED)
		{
			fprintf(stderr, "failed to mmap shm ring buffer\n");
			return 0;
		}

		SHMRingHeader	= (OutputHeader_t*)SHMMap;
		fprintf(stderr, "SHMRing Version :%08x ChunkSize:%i\n", SHMRingHeader->Version, SHMRingHeader->ChunkSize);
		assert(SHMRingHeader->Version == OUTPUT_VERSION_1_00);

		// reset get heade
		SHMRingData	= (u8*)(SHMRingHeader + 1);

		fprintf(stderr, "SHM Initial State Put:%08x Get:%08x\n", SHMRingHeader->Get, SHMRingHeader->Put);
	}

	// output + add all the ES targets
	struct Output_t* Out = Output_Create(	g_Output_NULL,
											g_Output_STDOUT, 
											g_Output_ESPush, 
											g_ESCompress, 
											g_ESNULL, 
											g_Output_BufferCnt,
											g_ESQueuePath,
											g_CPUOutput); 
	for (int i=0; i < g_ESHostCnt; i++)
	{
		Output_ESHostAdd(Out, g_ESHost[i].HostName, g_ESHost[i].HostPort);
	}

	// init flow state
	Flow_Open(Out, g_CPUFlow, g_FlowIndexDepth, g_FlowMax);

	u64 PacketTSFirst 	= 0;
	u64 PacketTSLast  	= 0;
	u64 TotalByteLast 	= 0;
	u64 TotalPktLast 	= 0;

	u64 OutputLineLast 	= 0;

	u64 PacketTSLastSample = 0;
	u64 DecodeTimeLast 	= 0;
	u64 DecodeTimeTSC 	= 0;


	while (!feof(FileIn))
	{
		u64 TSC = rdtsc();

		// progress stats
		if (TSC > PrintNextTSC)
		{
			PrintNextTSC = TSC + ns2tsc(1e9);

			u64 OutputByte = Output_TotalByteSent(Out);
			u64 OutputLine = Output_TotalLine(Out);	

			float bps = ((s_TotalByteWire - TotalByteLast) * 8.0) / (tsc2ns(TSC - LastTSC)/1e9); 
			float lps = (OutputLine - OutputLineLast) / (tsc2ns(TSC - LastTSC)/1e9); 
			float pps = (s_TotalPkt - TotalPktLast) / (tsc2ns(TSC - LastTSC)/1e9); 


			// is it keeping up ? > 1.0 means it will lag
			float PCAPWallTime 	= (PacketTSLast - PacketTSFirst) / 1e9;
			float DecodeTime 	= tsc2ns(DecodeTimeTSC) / 1e9; 

			// decode rate since last print
			float SamplePCAPWallTime 	= (PacketTSLast - PacketTSLastSample) / 1e9;
			float SampleDecodeTime 		= (DecodeTime - DecodeTimeLast) / 1e9; 

			float PCAPbps = ((s_TotalByteWire - TotalByteLast) * 8.0) / SamplePCAPWallTime; 

			float OutputWorkerCPU;
			float OutputWorkerCPURecv;
			u64 OutputPendingB;
			u64 OutputPushSizeB;
			Output_Stats(Out, 0,  &OutputWorkerCPU, NULL, NULL, &OutputWorkerCPURecv, NULL, &OutputPendingB, &OutputPushSizeB);

			u64 FlowCntSnapshot;	
			float FlowCPU;
			Flow_Stats(false, &FlowCntSnapshot, NULL, NULL, &FlowCPU, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

			fprintf(stderr, "[%s] %.3f/%.3f GB %.2f Mpps %.2f Gbps | cat %6.f MB %.2f %.2f %.2f | Flows/Snap: %6i FlowCPU:%.2f | ESPush:%6lli %6.2fK ESErr %4lli | OutCPU:%.2f OutPush: %.2f MB OutQueue:%6.1fMB\n", 

								FormatTS(PacketTSLast),

								s_TotalByteWire / (float)kGB(1), 
								OutputByte / (float)kGB(1), 
								pps / 1e6, 
								bps / 1e9, 

								s_StreamCAT_BytePending / (float)kMB(1),
								s_StreamCAT_CPUActive,
								s_StreamCAT_CPUFetch,
								s_StreamCAT_CPUSend,

								FlowCntSnapshot, 
								FlowCPU,
								Output_ESPushCnt(Out),
								lps/1e3,
								Output_ESErrorCnt(Out),
								OutputWorkerCPU,
								OutputPushSizeB / (float)kMB(1),
								OutputPendingB / (float)kMB(1) 
							);
			fflush(stderr);

			LastTSC 			= TSC;
			TotalByteLast		= s_TotalByteWire;
			TotalPktLast		= s_TotalPkt;
		
			OutputLineLast		= OutputLine;

			PacketTSLastSample 	= PacketTSLast;
			DecodeTimeLast 		= DecodeTime;
		}

		// dump performance stats every 1min
		if (TSC > ProfileNextTSC)
		{
			ProfileNextTSC = TSC + ns2tsc(60e9);
			ProfileDump(Out);
		}

		fProfile_Start(0, "Top");

		fProfile_Start(7, "PacketStall");

		PacketBuffer_t*	PktBlock = Flow_PacketAlloc();

		fProfile_Stop(7);

		fProfile_Start(6, "PacketFetch");

		// fill the pkt buffer up
		u32 PktCnt 		= 0;
		u32 ByteWire 	= 0;
		u32 ByteCapture = 0;

		u64 TSFirst		= 0;
		u64 TSLast		= 0;
	
		u32 Offset 		= 0;

		// PCAP format
		if (IsPCAP)
		{
			while (Offset < PktBlock->BufferMax - kKB(16))
			{
				PCAPPacket_t*	PktHeader	= (PCAPPacket_t*)(PktBlock->Buffer + Offset);
				
				// header
				int rlen = fread(PktHeader, 1, sizeof(PCAPPacket_t), FileIn);
				if (rlen != sizeof(PCAPPacket_t)) break;

				// validate size
				if ((PktHeader->LengthCapture == 0) || (PktHeader->LengthCapture > 128*1024)) 
				{
					fprintf(stderr, "Invalid packet length: %i\n", PktHeader->LengthCapture);
					break;
				}

				// payload
				rlen = fread(PktHeader + 1, 1, PktHeader->LengthCapture, FileIn);
				if (rlen != PktHeader->LengthCapture)
				{
					fprintf(stderr, "payload read fail %i expect %i\n", rlen, PktHeader->LengthCapture);
					break;
				}
				u64 TS = (u64)PktHeader->Sec * 1000000000ULL + (u64)PktHeader->NSec * TScale;
				u32 LengthWire 		= PktHeader->LengthWire;
				u32 LengthCapture 	= PktHeader->LengthCapture;
				u32 PortNo			= 0;

				// in-place conversion to FMAD Packet 
				FMADPacket_t* PktFMAD	= (FMADPacket_t*)PktHeader;
				PktFMAD->TS				= TS;
				PktFMAD->PortNo			= 0;
				PktFMAD->Flag			= 0;
				PktFMAD->LengthWire		= LengthWire;
				PktFMAD->LengthCapture	= LengthCapture;

				// next in packet block
				Offset += sizeof(PCAPPacket_t) + LengthCapture;

				// time range 
				if (TSFirst == 0) TSFirst = TS;
				TSLast = TS;

				PktCnt		+= 1;
				ByteWire	+= LengthWire; 
				ByteCapture	+= LengthCapture;
			}
		}
		// FMAD chunked format 
		if (IsFMAD)
		{
			FMADHeader_t Header;
			int rlen = fread(&Header, 1, sizeof(Header), FileIn);
			if (rlen != sizeof(Header))
			{
				fprintf(stderr, "FMADHeader read fail: %i %i : %i\n", rlen, sizeof(Header), errno, strerror(errno));
				break;
			}

			if (g_Verbose)
			{
				fprintf(stderr, "packet chunk0: PktCnt:%i TSFirst:%lli TSLast:%lli Length:%i Wire:%i Capture:%i\n", 
						Header.PktCnt,
						Header.TSStart,
						Header.TSEnd,	
						Header.Length,
						Header.BytesWire,
						Header.BytesCapture
						);
			}

			// sanity checks
			assert(Header.Length < 1024*1024);
			assert(Header.PktCnt < 1e6);

			rlen = fread(PktBlock->Buffer, 1, Header.Length, FileIn);
			if (rlen != Header.Length)
			{
				fprintf(stderr, "FMADHeader payload read fail: %i %i : %i\n", rlen, Header.Length, errno, strerror(errno));
				break;
			}

			PktCnt		= Header.PktCnt; 
			ByteWire	= Header.BytesWire;
			ByteCapture	= Header.BytesCapture;
			TSFirst		= Header.TSStart;
			TSLast		= Header.TSEnd;
			Offset		= Header.Length;

			if (g_Verbose)
			{
				fprintf(stderr, "packet chunk1: PktCnt:%i TSFirst:%lli TSLast:%lli Length:%i\n", 
						PktCnt,
						TSFirst,
						TSLast,
						Offset);
			}

			s_StreamCAT_BytePending = Header.BytePending;
			s_StreamCAT_CPUActive   = Header.CPUActive / (float)0x10000;
			s_StreamCAT_CPUFetch    = Header.CPUFetch / (float)0x10000;
			s_StreamCAT_CPUSend     = Header.CPUSend / (float)0x10000;
		}

		if (IsFMADRING)
		{

			fProfile_Start(5, "PacketFetch_Ring");

			// wait foe new data
			bool IsExit = false;
			while (SHMRingHeader->Get == SHMRingHeader->Put)
			{
				if (SHMRingHeader->End == SHMRingHeader->Get)
				{
					fprintf(stderr, "end of capture End:%08x Put:%08x Get:%08x\n", SHMRingHeader->End, SHMRingHeader->Put, SHMRingHeader->Get);
					IsExit = true;
					break;
				}
				//usleep(0);
				ndelay(100);
			}
			fProfile_Stop(5);

			if (IsExit) break;

			// get the chunk header info

			u32 Index 	= SHMRingHeader->Get & SHMRingHeader->Mask;	
			FMADHeader_t* Header = (FMADHeader_t*)(SHMRingData + Index * SHMRingHeader->ChunkSize);

			PktCnt		= Header->PktCnt; 
			ByteWire	= Header->BytesWire;
			ByteCapture	= Header->BytesCapture;
			TSFirst		= Header->TSStart;
			TSLast		= Header->TSEnd;
			Offset		= Header->Length;

			// copy to local buffer
	 		memcpy(PktBlock->Buffer, Header + 1, Header->Length);

			// signal its been consued to stream_cat
			SHMRingHeader->Get++;
		}

		// general stats on the packet block
		PktBlock->PktCnt 		= PktCnt;
		PktBlock->ByteWire 		= ByteWire;
		PktBlock->ByteCapture 	= ByteCapture;
		PktBlock->TSFirst 		= TSFirst;
		PktBlock->TSLast 		= TSLast;
		PktBlock->BufferLength 	= Offset;

		// wall time calcs
		if (PacketTSFirst == 0) PacketTSFirst = TSFirst;
		PacketTSLast 	= TSLast;

		fProfile_Stop(6);
		u64 TSC0 		= rdtsc();

		fProfile_Start(8, "PacketQueue");

		// queue the packet for processing 
		Flow_PacketQueue(PktBlock);

		fProfile_Stop(8);

		DecodeTimeTSC 	+= rdtsc() -  TSC0;

		s_TotalPkt			+= PktCnt;
		s_TotalByteCapture	+= ByteCapture; 
		s_TotalByteWire		+= ByteWire; 

		fProfile_Stop(0);
	}
	fProfile_Stop(6);
	fProfile_Stop(0);

	// flush any remaining flows
	Flow_Close(Out, PacketTSLast);

	// shutdown/flush the output
	Output_Close(Out);

	ProfileDump(Out);

	// final stats

	u64 TS1 = clock_ns();
	float dT = (TS1 - TS0) / 1e9;

	float Wirebps 		= (s_TotalByteWire * 8.0) / dT;
	float Capturebps 	= (s_TotalByteCapture * 8.0) / dT;
	float pps 			= s_TotalPkt / dT;

	float obps = (Output_TotalByteSent(Out) * 8.0) / dT;

	u64 TotalLine = Output_TotalLine(Out);	
	float lps = TotalLine / dT;

	float PCAPWallTime = (PacketTSLast - PacketTSFirst) / 1e9;
	fprintf(stderr, "PCAPWall time: %.2f sec ProcessTime %.2f sec (%.3f)\n", PCAPWallTime, dT, dT / PCAPWallTime);

	fprintf(stderr, "Total Time: %.2f sec RawInput[Wire %.3f Gbps Capture %.3f Gbps %.3f Mpps] Output[%.3f Gbps] TotalLine:%lli %.f Line/Sec\n", 
			dT, 
			Wirebps / 1e9, 
			Capturebps / 1e9, 
			pps/1e6, 

			obps / 1e9, 
			TotalLine, 
			lps); 
}

/* vim: set ts=4 sts=4 */
