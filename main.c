//
// Copyright (c) 2018 fmad engineering llc 
//
// The Creative Commons BY-NC 4.0 International License see LICENSE file for details 
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

// --shmring
// Ingress TotalPkt:86788192 TotalCapture:15348760584 TotalWire:98697500569    

// --chunked
// Ingress TotalPkt:86788192 TotalCapture:15348760584 TotalWire:98697500569 PayloadCRC:2a1fbc88 

// Ingress TotalPkt:86780961 TotalCapture:15346677399 TotalWire:98611504825 PayloadCRC:23ec2c6e  -- shm
// Ingress TotalPkt:86780961 TotalCapture:15346677399 TotalWire:98611504825 PayloadCRC:2319d85f  -- chunk
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
#include "tcpevent.h"

double TSC2Nano = 0;

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

	volatile u64	HBGetTSC;				// heart beat for consumer 
	volatile u64	HBPutTSC;				// heart beat for producer 

	u64				pad2[16 - 7];

} OutputHeader_t;


//---------------------------------------------------------------------------------------------
// tunables
bool			g_Verbose			= false;				// verbose print mode
s32				g_CPUCore[2]		= {14, 12};				// which CPU to run the main flow logic on
s32				g_CPUFlowCnt		= 4;					// total number of cpus for flow calcuiatoin			
s32				g_CPUFlow[128]		= { 19, 20, 21, 22};	// cpu mapping for flow threads
s32				g_CPUOutput[128]	= { 25, 26, 27, 28, 25, 26, 27, 28};	// cpu mappings for output threads 

bool			g_IsJSONPacket		= false;			// output JSON packet info 
bool			g_IsJSONFlow		= true;				// output JSON flow format

s64				g_FlowSampleRate	= 100e6;			// default to flow sample rate of 100msec
bool			g_IsFlowNULL		= false;			// benchmarking NULL flow rate 
u32				g_FlowIndexDepth	= 6;				// number of parallel flow index structures to allocate
														// ideally should == flow CPU count
u64				g_FlowMax			= 250e3;			// maximum number of flows per snapshot
bool			g_FlowTopNEnable	= false;			// enable or disable output the top N flows
u32				g_FlowTopNMax		= 1000;				// number of top flow to output
u8				g_FlowTopNMac		= 0;				// count of topN flows for particuar MAC address
u8				g_FlowTopNsMac[MAX_TOPN_MAC][6];		// topN source MAC
u8				g_FlowTopNdMac[MAX_TOPN_MAC][6];		// topN destination MAC
u8*				g_FlowIndexRollRead	= NULL;				// read the last (partial) snapshot to disk
u8*				g_FlowIndexRollWrite= NULL;				// write the last (partial) snapshot to disk
														// used so durning capture roll there is a single snapshot
														// instead of multiple json etnries 

bool			g_Output_NULL		= false;			// benchmarking mode output to /dev/null 
bool			g_Output_STDOUT		= true;				// by default output to stdout 
u8*				g_Output_PipeName	= NULL;				// name of pipe to output to
bool			g_Output_TCP_STDOUT	= false;			// by default output TCP to stdout
u8*			g_Output_TCP_PipeName	= NULL;			// name of TCP out pipe

struct TCPEventFilter g_TCPEventFilter = { true, true, true };

u32				g_Output_BufferCnt	= 64;				// number of output buffers
bool			g_Output_Keepalive	= false;			// ES connection would be keepalive/persistent
bool			g_Output_FilterPath	= false;			// use filter_path to return only took,errors on _bulk upload 
u32				g_Output_ThreadCnt  = 32;				// number of worker threads to use for ES push
u32				g_Output_MergeMin	= 1;				// minimum number of blocks to merge on output 
u32				g_Output_MergeMax	= 64;				// maximum number of blocks to merge on output 

u8 				g_CaptureName[256];						// name of the capture / index to push to
u8				g_DeviceName[128];						// name of the device this is sourced from

u64				s_TotalPkt			= 0;				// total packets processed
u64				s_TotalEvents		= 0;				// total events generated
u64				s_TotalByteCapture	= 0;				// total bytes captured 
u64				s_TotalByteWire		= 0;				// total bytes on the wire incomming 

u8				g_InstanceID			= 0;			// instance id 
u8				g_InstanceMax			= 0;			// total number of instances 

u64				s_StreamCAT_BytePending = 0;			// number of bytes pending in stream cat
float			s_StreamCAT_CPUActive 	= 0;			// stream_cat cpu active pct
float			s_StreamCAT_CPUFetch 	= 0;			// stream_cat cpu fetch from stroage utilization 
float			s_StreamCAT_CPUSend 	= 0;			// stream_cat cpu send down pipe utilization 

bool			g_Output_Histogram		= false;		// generate histograms file
FILE			*g_Output_Histogram_FP	= NULL;			// histogram file pointer

bool			g_ICMPOverwrite			= false;		// overwrite IP information for ICMP unreachable messages 

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
	fprintf(stderr, " --index-name <name>                : capture name to use for ES Index data\n");
	fprintf(stderr, " --verbose                          : verbose output\n");
	fprintf(stderr, " --config <confrig file>            : read from config file\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " --cpu-core   <cpu no>              : cpu map for core thread\n"); 
	fprintf(stderr, " --cpu-flow   <n> <cpu0..cpu n-1>   : cpu count and map for flow threads\n"); 
	fprintf(stderr, " --cpu-output <n> <cpu0..cpu n-1>   : cpu map for output threads\n"); 
	fprintf(stderr, "\n");
	fprintf(stderr, " --json-packet                      : write JSON packet data\n");
	fprintf(stderr, " --json-flow                        : write JSON flow data\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "Instance Info\n");
	fprintf(stderr, " --instance-id						 : instance id of this pcap2json FE\n");
	fprintf(stderr, " --instance-max					 : total number of pcap2json FE instances\n");

	fprintf(stderr, "Output Mode\n");
	fprintf(stderr, " --output-stdout                    : writes output to STDOUT\n");
	fprintf(stderr, " --output-espush                    : writes output directly to ES HTTP POST \n");
	fprintf(stderr, " --output-histogram <filename>      : Enable histogram output and writes it to file\n");
	fprintf(stderr, " --output-buffercnt <pow2 cnt>      : number of output buffers (default is 64)\n");
	fprintf(stderr, " --output-keepalive                 : enable keep alive (persistent) ES connection\n");
	fprintf(stderr, " --output-filterpath                : reduce data back from the ES cluster\n");
	fprintf(stderr, " --output-threadcnt                 : number of worker threads for ES push (default is 32)\n");
	fprintf(stderr, " --output-mergemin                  : minimum number of blocks to merge on output\n");
	fprintf(stderr, " --output-mergemax                  : maximum number of blocks to merge on output\n");

	fprintf(stderr, "\n");
	fprintf(stderr, "Flow specific options\n");
	fprintf(stderr, " --flow-samplerate <nanos>          : scientific notation flow sample rate. default 100e6 (100msec)\n");
	fprintf(stderr, " --flow-index-depth <number>        : number of root flow index to allocate defulat 6\n");
	fprintf(stderr, " --flow-max   <number>              : maximum number of flows (default 250e3)6\n");
	fprintf(stderr, " --flow-top-n <number>              : only output the top N flows\n"); 
	fprintf(stderr, " --flow-top-n-circuit <sMAC_dMAC>   : output top N flows based on specified src/dest MAC\n"); 
	fprintf(stderr, " --flow-template \"<template>\"     : Use a customized template for JSON output\n"); 
	fprintf(stderr, " --flow-roll-read \"temp file\"     : Capture roll read parital snapshot to disk\n"); 
	fprintf(stderr, " --flow-roll-write \"temp file\"    : Capture roll write parital snapshot to disk\n"); 

	fprintf(stderr, "\n");
	fprintf(stderr, "Elastic Stack options\n");
	fprintf(stderr, " --es-host <hostname:port>          : Sets the ES Hostname\n");
	fprintf(stderr, " --es-timeout <timeout>             : Sets ES connection timeout in milliseconds (Default: 2000 msec)\n");
	fprintf(stderr, " --es-compress                      : enables gzip compressed POST\n");
	fprintf(stderr, " --es-null                          : use ES Null target for perf testing\n");
	fprintf(stderr, " --es-queue-path                    : ES Output queue is file backed\n");

	fprintf(stderr, "\n");
	fprintf(stderr, "ICMP options\n");
	fprintf(stderr, " --icmp-overwrite                   : overwrite IP Proto info for ICMP packets\n");
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
		// cmd line arg
		cnt++;

		// number of cpus allocated to flow calculation
		g_CPUFlowCnt = atoi(argv[1]);
		cnt++;
		fprintf(stderr, "  Flow on CPU (%i) ", g_CPUFlowCnt); 

		for (int i=0; i < g_CPUFlowCnt; i++)
		{
			g_CPUFlow[i] = atoi(argv[2 + i]);
			cnt++;

			fprintf(stderr, "%i ", g_CPUFlow[i]); 
		}
		fprintf(stderr, "\n");
	}
	if (strcmp(argv[0], "--cpu-output") == 0)
	{
		u32 Cnt = atoi(argv[1]);

		g_CPUOutput[0] = atoi(argv[2]);
		g_CPUOutput[1] = atoi(argv[3]);
		g_CPUOutput[2] = atoi(argv[4]);
		g_CPUOutput[3] = atoi(argv[5]);
		fprintf(stderr, "  Output on CPU %i %i %i %i\n", 
							g_CPUOutput[0], g_CPUOutput[1], g_CPUOutput[2], g_CPUOutput[3] );
		cnt	+= 4 + 1 + 1;
	}
	// output json packet data 
	if (strcmp(argv[0], "--json-packet") == 0)
	{
		fprintf(stderr, "  Write JSON Packet meta data\n");
		g_IsJSONFlow 	= false;	
		g_IsJSONPacket 	= true;	
		cnt	+= 1;
	}
	// output json flow data 
	if (strcmp(argv[0], "--json-flow") == 0)
	{
		fprintf(stderr, "  Write JSON Flow meta data\n");
		g_IsJSONFlow 	= true;	
		g_IsJSONPacket 	= false;	
		cnt	+= 1;
	}
	// capture name 
	if (strcmp(argv[0], "--index-name") == 0)
	{
		strncpy(g_CaptureName, argv[1], sizeof(g_CaptureName));	
		fprintf(stderr, "  Capture Name[%s]\n", g_CaptureName);
		cnt	+= 2;
	}

	// instance id of this app 
	if (strcmp(argv[0], "--instance-id") == 0)
	{
		g_InstanceID 	=  atoi(argv[1]);
		fprintf(stderr, "  Instance ID:%i\n", g_InstanceID);
		cnt	+= 2;
	}
	// total number of instnacesc 
	if (strcmp(argv[0], "--instance-max") == 0)
	{
		g_InstanceMax 	=  atoi(argv[1]);
		fprintf(stderr, "  Instance Max:%i\n", g_InstanceMax);
		cnt	+= 2;
	}

	// icmp overwrite mode 
	if (strcmp(argv[0], "--icmp-overwrite") == 0)
	{
		fprintf(stderr, "  ICMP Overwrite Mode\n"); 
		cnt	+= 1;
		g_ICMPOverwrite = true;
	}

	// benchmarking write to /dev/null 
	if (strcmp(argv[0], "--output-null") == 0)
	{
		g_Output_NULL 	= true;
		fprintf(stderr, "  Output to NULL\n");
		cnt	+= 1;
	}
	// default output to stdout
	if (strcmp(argv[0], "--output-stdout") == 0)
	{
		g_Output_NULL 	= false;
		g_Output_STDOUT = true;
		fprintf(stderr, "  Output to STDOUT\n");
		cnt	+= 1;
	}
	// write to a named pipe 
	if (strcmp(argv[0], "--output-pipe") == 0)
	{
		g_Output_NULL 		= false;
		g_Output_STDOUT 	= false;
		g_Output_PipeName	= strdup(argv[1]);
		fprintf(stderr, "  Output to Pipe (%s)\n", g_Output_PipeName);
		cnt	+= 2;
	}
	// default tcp output to stdout
	if (strcmp(argv[0], "--output-tcp-stdout") == 0)
	{
		g_Output_TCP_STDOUT = true;
		fprintf(stderr, "  Output TCP events to STDOUT\n");
		cnt	+= 1;
	}
	// write tcp events to a named pipe
	if (strcmp(argv[0], "--output-tcp-pipe") == 0)
	{
		g_Output_TCP_STDOUT = false;
		g_Output_TCP_PipeName	= strdup(argv[1]);
		fprintf(stderr, "  Output TCP events to Pipe (%s)\n", g_Output_TCP_PipeName);
		cnt	+= 2;
	}
	// filter which tcp events are output
	if (strcmp(argv[0], "--tcp-events") == 0)
	{
		if (!strstr(argv[1], "all"))
		{
			// We're filtering events, so turn them all off first
			memset(&g_TCPEventFilter, 0, sizeof(g_TCPEventFilter));
		}

		if (strstr(argv[1], "netRTT"))
		{
			g_TCPEventFilter.netRTT = true;
		}
		if (strstr(argv[1], "appRTT"))
		{
			g_TCPEventFilter.appRTT = true;
		}
		if (strstr(argv[1], "window"))
		{
			g_TCPEventFilter.window = true;
		}

		fprintf(stderr, "  Filter TCP events (%s netRTT=%d appRTT=%d window=%d)\n", argv[1], g_TCPEventFilter.netRTT, g_TCPEventFilter.appRTT, g_TCPEventFilter.window);

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
	// flow capture roll 
	if (strcmp(argv[0], "--flow-roll-read") == 0)
	{
		g_FlowIndexRollRead =  strdup(argv[1]); 
		fprintf(stderr, "  Flow Roll Read [%s]\n", g_FlowIndexRollRead); 
		cnt	+= 2;
	}
	if (strcmp(argv[0], "--flow-roll-write") == 0)
	{
		g_FlowIndexRollWrite =  strdup(argv[1]); 
		fprintf(stderr, "  Flow Roll Write [%s]\n", g_FlowIndexRollWrite); 
		cnt	+= 2;
	}


	// create a unique id so calling applications
	// can identify it with ps 
	if (strcmp(argv[0], "--uid") == 0)
	{
		u8* uid = argv[1];
		fprintf(stderr, "  UID [%s]\n", uid); 
		cnt	+= 2;
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
	u8  LineBuffer[16*1024];
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
/*
	float	OutputWorkerCPU;
	float	OutputWorkerCPUCompress;
	float	OutputWorkerCPUSend;
	float	OutputWorkerCPURecv;
	u64		OutputTotalCycle;
	u64		OutputPendingByte;
	u64		OutputPushSizeByte;
	u64		OutputPushBps;
	Output_Stats(Out, 1,  	&OutputWorkerCPU, 
							&OutputWorkerCPUCompress, 
							&OutputWorkerCPUSend, 
							&OutputWorkerCPURecv,
							&OutputTotalCycle,
							&OutputPendingByte,
							&OutputPushSizeByte,
							&OutputPushBps);

	fprintf(stderr, "Output Worker CPU\n");
	fprintf(stderr, "  Top      : %.6f\n", OutputWorkerCPU);
	fprintf(stderr, "  Compress : %.6f\n", OutputWorkerCPUCompress);
	fprintf(stderr, "  Send     : %.6f\n", OutputWorkerCPUSend);
	fprintf(stderr, "  Recv     : %.6f\n", OutputWorkerCPURecv);
	fprintf(stderr, "  Total    : %.6f sec\n", tsc2ns(OutputTotalCycle)/1e9 );
	fprintf(stderr, "  Pending  : %.6f MB\n", OutputPendingByte  / (float)kMB(1)); 
	fprintf(stderr, "  PushSize : %.2f MB\n", OutputPushSizeByte / (float)kMB(1)); 
	fprintf(stderr, "  PushSpeed: %.2f Gbps\n", OutputPushBps / 1e9); 
	fprintf(stderr, "\n");

*/

	u64 FlowCntSnapshot		= 0;
	u64 PktCntSnapshot 		= 0;
	u64 FlowCntTotal 		= 0;
	float FlowDepthMean		= 0;
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
				&FlowDepthMean, 
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
// busy wait update
static OutputHeader_t* s_SHMRingHeader	= NULL; 
static void SHMRingBusyWait(void)
{
	//fprintf(stderr, "ring hb %p\n", s_SHMRingHeader);
	s_SHMRingHeader->HBGetTSC = rdtsc();
}

static void DefaultBusyWait(void)
{
	//fprintf(stderr, "default busy wait\n");
}

typedef void BusyWait_f(void);
BusyWait_f*  g_BusyWaitFn = &DefaultBusyWait;

//---------------------------------------------------------------------------------------------

int main(int argc, u8* argv[])
{
	fprintf(stderr, "pcap2json https://www.github/fmadio/pcap2json build:%s %s\n", __DATE__, __TIME__);

	// get the hosts name
	gethostname(g_DeviceName, sizeof(g_DeviceName));	

	u8 ClockStr[128];
	clock_str(ClockStr, clock_date() );

	sprintf(g_CaptureName, "%s-pcap2json_%s", g_DeviceName, ClockStr); 
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

	fprintf(stderr, "  Flow   (%i) ", g_CPUFlowCnt);
	for (int i=0; i < g_CPUFlowCnt; i++) fprintf(stderr, "%i ", g_CPUFlow[i]);
	fprintf(stderr, "\n");

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

	// chunked fmad buffer
	u8* FMADChunkBuffer = NULL; 

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

		// allocate buffer
		FMADChunkBuffer = malloc(1024*1024);
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
			return 0;
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
		assert(sizeof(OutputHeader_t) == 8*16*2);
		SHMRingData	= (u8*)(SHMRingHeader + 1);

		fprintf(stderr, "SHM Initial State Put:%08x Get:%08x\n", SHMRingHeader->Get, SHMRingHeader->Put);

		// set busy wait header
		s_SHMRingHeader	= SHMRingHeader;
		g_BusyWaitFn 	= &SHMRingBusyWait;
	}

	// output + add all the ES targets
	struct Output_t* Out = Output_Create(	g_Output_NULL,
											g_Output_STDOUT, 
											1,
											g_Output_PipeName,
											"FlowRecord_t",
											sizeof(FlowRecord_t),	
											g_CPUOutput
										);
	// TCP event output
	struct Output_t* OutTCP = Output_Create(	false,
											g_Output_TCP_STDOUT,
											1,
											g_Output_TCP_PipeName,
											"TCPEvent_t",
											sizeof(TCPEvent_t),
											g_CPUOutput
										);

	// init flow state
	Flow_Open(Out, OutTCP, g_CPUFlowCnt, g_CPUFlow, g_FlowIndexDepth, g_FlowMax);

	u64 PacketTSFirst 	= 0;
	u64 PacketTSLast  	= 0;
	u64 TotalByteLast 	= 0;
	u64 TotalPktLast 	= 0;

	u64 OutputLineLast 	= 0;

	u64 PacketTSLastSample = 0;
	u64 DecodeTimeLast 	= 0;
	u64 DecodeTimeTSC 	= 0;

	u32 PayloadCRC		= 0;
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
			u64 OutputLps;
			u64 OutputBps;
			Output_Stats(Out, true,  &OutputWorkerCPU, NULL, NULL, &OutputWorkerCPURecv, NULL, &OutputPendingB, &OutputLps, &OutputBps);

			u64 FlowCntSnapshot;	
			float FlowCPU;
			float FlowDepthMedian;
			float FlowCPUOutputStall;
			Flow_Stats(false, &FlowCntSnapshot, NULL, NULL, &FlowDepthMedian, &FlowCPU, NULL, NULL, &FlowCPUOutputStall, NULL, NULL, NULL, NULL);

			fprintf(stderr, "[%s] %lli %.3f/%.3f GB %8.2f Mpps %8.2f Gbps | cat %6.f MB %.2f %.2f %.2f | Flows/Snap: %6i:%4.f FlowCPU:%.2f %.2f | Output %9.3f K Lines/sec %6.3f Gbps\n", 

								FormatTS(PacketTSLast),
								PacketTSLast,

								s_TotalByteWire / (float)kGB(1), 
								OutputByte / (float)kGB(1), 
								pps / 1e6, 
								bps / 1e9, 

								s_StreamCAT_BytePending / (float)kMB(1),
								s_StreamCAT_CPUActive,
								s_StreamCAT_CPUFetch,
								s_StreamCAT_CPUSend,

								FlowCntSnapshot, 
								FlowDepthMedian,
								FlowCPU,
								FlowCPUOutputStall,
								(float)(OutputLps / 1e3),
								(float)(OutputBps / 1e9)
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

		// keep trying until get an alloc
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

			for (int i=0; i < Header.Length; i++)
			{
				PayloadCRC += PktBlock->Buffer[i];
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
			do
			{
				// update SHM Ring HB 
				g_BusyWaitFn();

				// check producer is alive still & producer did not
				// exit due to end of stream
				s64 dTSC = rdtsc() - SHMRingHeader->HBPutTSC;
				if ((dTSC > 600e9) && (SHMRingHeader->End == -1))
				{
					fprintf(stderr, "producer timeout: %lli %.3f sec %i\n", dTSC, tsc2ns(dTSC)/1e9, SHMRingHeader->End);
					IsExit = true;
					break;
				}

				// there is data
				if (SHMRingHeader->Get != SHMRingHeader->Put) break;

				// check for end of stream
				if (SHMRingHeader->End == SHMRingHeader->Get)
				{
					fprintf(stderr, "end of capture End:%08x Put:%08x Get:%08x\n", SHMRingHeader->End, SHMRingHeader->Put, SHMRingHeader->Get);
					IsExit = true;
					break;
				}

				// wait a bit for a block to become ready
				//usleep(0);
				ndelay(250);

			} while (SHMRingHeader->Get == SHMRingHeader->Put);

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
			assert(Header->Length < PktBlock->BufferMax);
	 		memcpy(PktBlock->Buffer, Header + 1, Header->Length);

			/*
			u32 CRC = 0;
			u8* D8 = (u8*)(Header + 1);
			for (int i=0; i < Header->Length; i++)
			{
				//CRC += PktBlock->Buffer[i];

				CRC += D8[i]; 
			}

			//u16 CRC16 = (CRC & 0xffff) ^ (CRC >> 16); 
			//if (CRC16 != Header->CRC16)
			//{
			//	fprintf(stderr, "CRC16 error Found:%04x Expect %04x Length:%i Put:%08x Get:%08x\n", CRC16, Header->CRC16, Header->Length, SHMRingHeader->Put, SHMRingHeader->Get);
			//	assert(false);
			//}
			PayloadCRC += CRC;
			*/

			// copy stream cat stats
			s_StreamCAT_BytePending = Header->BytePending;
			s_StreamCAT_CPUActive   = Header->CPUActive / (float)0x10000;
			s_StreamCAT_CPUFetch    = Header->CPUFetch / (float)0x10000;
			s_StreamCAT_CPUSend     = Header->CPUSend / (float)0x10000;

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
		if (TSLast != 0) 		PacketTSLast 	= TSLast;

		fProfile_Stop(6);
		u64 TSC0 		= rdtsc();

		fProfile_Start(8, "PacketQueue");

		// queue the packet for processing 
		Flow_PacketQueue(PktBlock, false);

		fProfile_Stop(8);

		DecodeTimeTSC 	+= rdtsc() -  TSC0;

		s_TotalPkt			+= PktCnt;
		s_TotalByteCapture	+= ByteCapture; 
		s_TotalByteWire		+= ByteWire; 

		fProfile_Stop(0);
	}
	fProfile_Stop(6);
	fProfile_Stop(0);

	fprintf(stderr, "pipe exit %s %lli\n", FormatTS(PacketTSLast), PacketTSLast);
	fflush(stderr);

	// flush any remaining flows
	Flow_Close(Out, PacketTSLast);

	// shutdown/flush the output
	Output_Close(Out);
	Output_Close(OutTCP);

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
	fprintf(stderr, "Ingress TotalPkt:%lli TotalEvent:%lli TotalCapture:%lli TotalWire:%lli PayloadCRC:%08x\n", s_TotalPkt, s_TotalEvents, s_TotalByteCapture, s_TotalByteWire, PayloadCRC);

	fprintf(stderr, "Total Time: %.2f sec RawInput[Wire %.3f Gbps Capture %.3f Gbps %.3f Mpps] Output[%.3f Gbps] TotalLine:%lli %.f Line/Sec\n", 
			dT, 
			Wirebps / 1e9, 
			Capturebps / 1e9, 
			pps/1e6, 

			obps / 1e9, 
			TotalLine, 
			lps); 

	// dump final SHM ring header stats
	if (IsFMADRING)
	{
		fprintf(stderr, "SHMRing Put %i Get %i\n", SHMRingHeader->Put, SHMRingHeader->Get);
	}
	if (g_Output_Histogram)
	{
		fclose(g_Output_Histogram_FP);
		g_Output_Histogram_FP = NULL;
	}
}

/* vim: set ts=4 sts=4 */
