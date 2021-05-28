//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The Creative Commons BY-NC 4.0 International License see LICENSE file for details 
// 
// guts of the flow calcuation. generats a SHA1 of the MAC/IP/Proto/Port
// and maps packets into this
// source upload:
// fmadio@fmadio40v2-194:/mnt/store1/tmp$ lz4 -d -c interop17_hotstage_20170609_133953.717.953.280.pcap.lz4  | sudo stream_upload --time-compress 100 --slice 192 --name interop17
//
// upload reference stats
//
// Total Packets: 86780961
// TotalBytes     : 98611504825
// TotalPackets   : 86780961
// PayloadCRC     : 58321125ac63e0b8
// ErrorSeq       : 0
// ErrorPktSize   : 0
// LastByte       : 0x00000000
// SeqStart       : 0x00000000 0x00000000 0x00000000 0x00000000 : 0x00000000
// SeqEnd         : 0x00000000 0x00000000 0x00000000 0x00000000 : 0x00000000
// PacketCnt      : 0 0 0 0
// TimeOrder      : 0
// CRCFail        : 0
// Time First     : 20170609_223953 13:39:53.717.953.280
// Time Last      : 20170609_223956 13:39:56.807.825.664
// TotalPCAPTime  : 3089872384 ns
// Bandwidth      : 255.315 Gbps
// Packet Rate    : 28.086 Mpps
//
//
// on the interop timecompressed(x100) + (192B sliced) data following performance is seen
//
//
// interop_scaled_20181204_2054     15GB Chunk(Cnt:   63842 Start: 4100250 End: 4164091 Comp:1.49) Inv:-nan Cap:-nan CacheI:-nan Cache:-nan Disk:-nan Drop:-nan Pkt:0
//
//
// 2018/12/07:   ~ 17Gbps ingress @ 43K flows per snapshot
//
// [11:54:56.639.887.104] Input:29.964 GB  17.00 Gbps PCAP: 248.85 Gbps | Output 0.27410 GB Flows/Snap:  42113 FlowCPU:0.617 | ESPush:       0  42.64K ESErr    0 | OutputCPU: 0.000
// [11:54:56.705.689.088] Input:31.911 GB  16.73 Gbps PCAP: 254.24 Gbps | Output 0.27439 GB Flows/Snap:  43165 FlowCPU:0.617 | ESPush:       0   0.53K ESErr    0 | OutputCPU: 0.000
// [11:54:56.768.221.696] Input:33.900 GB  17.09 Gbps PCAP: 273.26 Gbps | Output 0.29819 GB Flows/Snap:  43591 FlowCPU:0.619 | ESPush:       0  43.59K ESErr    0 | OutputCPU: 0.000
// [11:54:56.831.990.784] Input:35.886 GB  17.05 Gbps PCAP: 267.44 Gbps | Output 0.31004 GB Flows/Snap:  43591 FlowCPU:0.616 | ESPush:       0  22.04K ESErr    0 | OutputCPU: 0.000
//
// 2018/12/27
// 
// PCAP interface using packet blocks
//
// [11:53:14.433.064.192] In:55.479 GB 2.52 Mpps 22.98 Gbps PCAP: 251.61 Gbps | Out 0.46024 GB Flows/Snap:  42101 FlowCPU:0.31 | ESPush:     0  42.09K ESErr    0 | OutCPU: 0.00 (0.00)
// [11:53:14.524.824.832] In:58.166 GB 2.53 Mpps 23.08 Gbps PCAP: 251.52 Gbps | Out 0.48452 GB Flows/Snap:  44751 FlowCPU:0.32 | ESPush:     0  44.75K ESErr    0 | OutCPU: 0.00 (0.00)
// [11:53:14.611.949.056] In:60.846 GB 2.55 Mpps 23.02 Gbps PCAP: 264.30 Gbps | Out 0.50738 GB Flows/Snap:  41926 FlowCPU:0.32 | ESPush:     0  41.92K ESErr    0 | OutCPU: 0.00 (0.00)
//
// PCAPWall time: 3.09 sec ProcessTime 37.40 sec (12.105)
//
// 2018/12/28
//
// FMAD chunked format + per CPU FlowIndex with Merged output 
//
// [00:26:29.381.616.896] In:42.241 GB 6.75 Mpps 61.25 Gbps PCAP: 254.51 Gbps | Out 0.36618 GB Flows/Snap:  40431 FlowCPU:0.87 | ESPush:     0  97.81K ESErr    0 | OutCPU: 0.00 (0.00)
// [00:26:29.620.605.696] In:49.352 GB 6.73 Mpps 61.08 Gbps PCAP: 255.59 Gbps | Out 0.42603 GB Flows/Snap:  55289 FlowCPU:0.87 | ESPush:     0 109.22K ESErr    0 | OutCPU: 0.00 (0.00)
// [00:26:29.864.099.840] In:56.482 GB 6.70 Mpps 61.25 Gbps PCAP: 251.53 Gbps | Out 0.47893 GB Flows/Snap:  42116 FlowCPU:0.87 | ESPush:     0  96.60K ESErr    0 | OutCPU: 0.00 (0.00)
// [00:26:30.089.333.248] In:63.266 GB 6.45 Mpps 58.26 Gbps PCAP: 258.71 Gbps | Out 0.56736 GB Flows/Snap:  44352 FlowCPU:0.88 | ESPush:     0 161.32K ESErr    0 | OutCPU: 0.00 (0.00)
//
// PCAPWall time: 16900787200.00 sec ProcessTime 17.74 sec (0.000)
// Total Time: 17.84 sec RawInput[44.211 Gbps 38906940 Pps] Output[0.469 Gbps] TotalLine:1909656 107021 Line/Sec
//
// 2019/01/07
//
// added 4 more CPUs (everything HWT1 Socket1) with ES Output code on Socket0
//
// [11:23:19.631.513.088] In:34.963 GB 6.63 Mpps 60.00 Gbps PCAP: 260.45 Gbps | Out 0.29738 GB Flows/Snap:  43298 FlowCPU:0.42 | ESPush:     0 105.85K ESErr    0 | OutCPU: 0.00 (0.00)
// [11:23:19.867.406.080] In:41.963 GB 6.63 Mpps 60.12 Gbps PCAP: 254.90 Gbps | Out 0.35608 GB Flows/Snap:  40994 FlowCPU:0.42 | ESPush:     0 107.84K ESErr    0 | OutCPU: 0.00 (0.00)
// [11:23:20.101.664.768] In:48.934 GB 6.60 Mpps 59.87 Gbps PCAP: 255.62 Gbps | Out 0.40198 GB Flows/Snap:  43311 FlowCPU:0.42 | ESPush:     0  83.93K ESErr    0 | OutCPU: 0.00 (0.00)
// [11:23:20.340.847.872] In:55.938 GB 6.57 Mpps 60.16 Gbps PCAP: 251.55 Gbps | Out 0.46324 GB Flows/Snap:  43397 FlowCPU:0.42 | ESPush:     0 111.99K ESErr    0 | OutCPU: 0.00 (0.00)
// [11:23:20.572.062.208] In:62.882 GB 6.60 Mpps 59.65 Gbps PCAP: 258.00 Gbps | Out 0.51774 GB Flows/Snap:  44421 FlowCPU:0.41 | ESPush:     0 100.49K ESErr    0 | OutCPU: 0.00 (0.00)
// [11:23:20.802.807.808] In:69.805 GB 6.60 Mpps 59.45 Gbps PCAP: 257.70 Gbps | Out 0.56472 GB Flows/Snap:  41743 FlowCPU:0.41 | ESPush:     0  86.64K ESErr    0 | OutCPU: 0.00 (0.00)
//
// PCAPWall time: 16899884032.00 sec ProcessTime 15.72 sec (0.000)
// Total Time: 15.72 sec RawInput[50.191 Gbps 44169856 Pps] Output[0.390 Gbps] TotalLine:1396322 88838 Line/Sec
//
// 2019/2/01
//
// flow indexs now run up 6 entries wide, snapshot(0....5) all running lockless
// removed OutputLine to a an OutputBuffer dramatically reducing the lock collisions
//
// [00:02:56.709.989.120] 50.771/0.384 GB 9.69 Mpps 88.15 Gbps | cat   7140 MB 1.00 0.50 0.27 | Flows/Snap:  42518 FlowCPU:0.60 | ESPush:     0 140.65K ESErr    0 | OutCPU: 0.00 (0.00)
// [00:02:57.055.932.160] 61.032/0.461 GB 9.68 Mpps 88.14 Gbps | cat   5357 MB 1.00 0.51 0.27 | Flows/Snap:  44755 FlowCPU:0.60 | ESPush:     0 153.84K ESErr    0 | OutCPU: 0.00 (0.00)
// [00:02:57.397.079.040] 71.246/0.533 GB 9.71 Mpps 87.74 Gbps | cat   3573 MB 1.00 0.50 0.28 | Flows/Snap:  40849 FlowCPU:0.60 | ESPush:     0 142.27K ESErr    0 | OutCPU: 0.00 (0.00)
//
// PCAPWall time: 16897678336.00 sec ProcessTime 13.11 sec (0.000)
// Total Time: 13.11 sec RawInput[Wire 60.155 Gbps Capture 9.362 Gbps 53 Mpps] Output[0.454 Gbps] TotalLine:1365000 104084 Line/Sec
//
// 2019/2/01
//
// changed flow hash index to use lazy state clear, helps alot to churn though low bandwidth large PCAPs
//
// [00:02:56.342.157.568] 39.904/0.306 GB 9.57 Mpps 86.55 Gbps | cat   9028 MB 1.00 0.50 0.28 | Flows/Snap:  44359 FlowCPU:0.61 | ESPush:     0 144.36K ESErr    0 | OutCPU: 0.00 (0.00) OutQueue:313.03MB
// [00:02:56.677.250.816] 49.812/0.379 GB 9.35 Mpps 85.10 Gbps | cat   7306 MB 1.00 0.50 0.28 | Flows/Snap:  42340 FlowCPU:0.61 | ESPush:     0 145.37K ESErr    0 | OutCPU: 0.00 (0.00) OutQueue:388.46MB
// [00:02:57.018.342.912] 59.894/0.449 GB 9.49 Mpps 86.59 Gbps | cat   5557 MB 1.00 0.49 0.28 | Flows/Snap:  44757 FlowCPU:0.61 | ESPush:     0 137.58K ESErr    0 | OutCPU: 0.00 (0.00) OutQueue:459.55MB
// [00:02:57.349.965.824] 69.852/0.521 GB 9.50 Mpps 85.53 Gbps | cat   3814 MB 1.00 0.50 0.28 | Flows/Snap:  41777 FlowCPU:0.61 | ESPush:     0 143.19K ESErr    0 | OutCPU: 0.00 (0.00) OutQueue:533.33MB
//
// PCAPWall time: 16897678336.00 sec ProcessTime 12.65 sec (0.000)
// Total Time: 12.65 sec RawInput[Wire 62.342 Gbps Capture 9.702 Gbps 55 Mpps] Output[0.471 Gbps] TotalLine:1365062 107874 Line/Sec
//
// 2019/8/12
//
// benchmark using Platnim 8160 CPU, mapping Core 50, flow 51-58, output 59-62
// nothing else has changed, same cpu counts just a new processor. As the CPU stalling shows its entirely stalled by stream_cat fetching capacity
//
// [13:39:55.589.688.832] 55.494/0.000 GB 8.70 Mpps 79.49 Gbps | cat   6324 MB 1.00 0.45 0.43 | Flows/Snap:  42331 FlowCPU:0.30 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 687.7MB
// [13:39:55.896.608.000] 64.767/0.000 GB 8.82 Mpps 79.65 Gbps | cat   4704 MB 1.00 0.45 0.43 | Flows/Snap:  44268 FlowCPU:0.30 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 796.5MB
// [13:39:56.192.491.008] 73.518/0.000 GB 8.30 Mpps 75.16 Gbps | cat   3178 MB 1.00 0.45 0.43 | Flows/Snap:  43490 FlowCPU:0.29 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 901.7MB
// [13:39:56.472.166.400] 81.811/0.000 GB 7.83 Mpps 71.24 Gbps | cat   1738 MB 1.00 0.45 0.42 | Flows/Snap:  45822 FlowCPU:0.29 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue:1014.6MB
// [13:39:56.759.885.056] 90.389/0.000 GB 8.06 Mpps 73.67 Gbps | cat    252 MB 1.00 0.46 0.41 | Flows/Snap:  45334 FlowCPU:0.29 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue:1129.2MB
//
// PCAPWall time: 16949728256.00 sec ProcessTime 12.78 sec (0.000)
// Total Time: 12.78 sec RawInput[Wire 61.713 Gbps Capture 9.604 Gbps 6.789 Mpps] Output[0.000 Gbps] TotalLine:0 0 Line/Sec
//
// 2019/8/13:
//
// using stream_cat slice 72B (instead of 128B) not sure if the above was using 128B or 72B
//
// sudo stream_cat --chunked --cpu 63 interop_20190812_1755 --pktslice 128 | /mnt/store0/git/pcap2json/pcap2json  --config /mnt/store0/etc/pcap2json.config
//
// [13:39:55.219.739.136] 44.601/0.000 GB 10.37 Mpps 94.07 Gbps | cat   8214 MB 1.00 0.57 0.31 | Flows/Snap:  41624 FlowCPU:0.38 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 581.8MB
// [13:39:55.593.488.896] 55.603/0.000 GB 10.36 Mpps 94.50 Gbps | cat   6306 MB 1.00 0.57 0.31 | Flows/Snap:  42331 FlowCPU:0.38 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 687.7MB
// [13:39:55.955.025.664] 66.539/0.000 GB 10.41 Mpps 93.93 Gbps | cat   4394 MB 1.00 0.57 0.31 | Flows/Snap:  42148 FlowCPU:0.38 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 831.5MB
// [13:39:56.330.177.792] 77.589/0.000 GB 10.47 Mpps 94.91 Gbps | cat   2469 MB 1.00 0.57 0.31 | Flows/Snap:  45309 FlowCPU:0.38 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 976.6MB
// [13:39:56.704.730.112] 88.713/0.000 GB 10.47 Mpps 95.55 Gbps | cat    541 MB 1.00 0.57 0.31 | Flows/Snap:  47187 FlowCPU:0.38 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue:1095.5MB
//
// PCAPWall time: 16949728256.00 sec ProcessTime 10.96 sec (0.000)
// Total Time: 10.96 sec RawInput[Wire 71.950 Gbps Capture 11.197 Gbps 7.915 Mpps] Output[0.000 Gbps] TotalLine:0 0 Line/Sec
//
// 2019/10/3
// 
// 96CPU 100Gv2 system with 24 CPUs for Flow calculation
//
// [13:39:54.677.221.888] 28.337/0.000 GB 13.39 Mpps 121.15 Gbps | cat  12140 MB 1.00 1.00 0.00 | Flows/Snap:  43880:   1 FlowCPU:0.27 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 370.0MB 0.000 Gbps
// [13:39:55.149.390.336] 42.485/0.000 GB 13.41 Mpps 121.52 Gbps | cat   9681 MB 1.00 1.00 0.00 | Flows/Snap:  40664:   1 FlowCPU:0.27 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 547.2MB 0.000 Gbps
// [13:39:55.628.859.392] 56.645/0.000 GB 13.35 Mpps 121.63 Gbps | cat   7221 MB 1.00 1.00 0.00 | Flows/Snap:  42331:   1 FlowCPU:0.26 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 717.2MB 0.000 Gbps
// [13:39:56.096.991.744] 70.709/0.000 GB 13.37 Mpps 120.81 Gbps | cat   4764 MB 1.00 1.00 0.00 | Flows/Snap:  41023:   1 FlowCPU:0.26 | ESPush:     0   0.00K ESErr    0 | OutCPU:0.00 OutPush: 0.00 MB OutQueue: 865.6MB 0.000 Gbps
//
// PCAPWall time: 16949728256.00 sec ProcessTime 8.04 sec (0.000)
// Total Time: 8.04 sec RawInput[Wire 98.087 Gbps Capture 15.265 Gbps 10.790 Mpps] Output[0.000 Gbps] TotalLine:0 0 Line/Sec
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
#include "output.h"
#include "flow.h"
#include "tcpevent.h"
#include "histogram.h"

typedef void BusyWait_f(void);
extern BusyWait_f*  g_BusyWaitFn;

void sha1_compress(uint32_t state[static 5], const uint8_t block[static 64]);

//---------------------------------------------------------------------------------------------
// SACK bit field
#define TCP_SACK_ENABLE			(1<<0)
#define TCP_SACK_GAP			(1<<1)
#define TCP_SACK_OPTION			(1<<2)

//---------------------------------------------------------------------------------------------

// top level flow index
typedef struct FlowIndex_t
{
	u64						FlowMax;			// maximum number of flows 
	FlowRecord_t*			FlowList;			// list of statically allocated flows
	u32*					FlowHash;			// flash hash index
	u16*					FlowHashFrameID;	// way to clear the flow hash without touching memory 
	u16						FrameID;			// current frame id

	u32						FlowLock;			// mutex to modify 

	u64						FlowCntSnapshot;	// number of flows in this snapshot
	u32						PktBlockCnt;		// current number of processes packet blocks 
	u32						PktBlockMax;		// number of packet blocks in this index
												// valid on root only

	u32						JSONBufferMax;		// total size of output buffer	
	u8*						JSONBuffer;			// small output buffer

	volatile bool			IsUse;

	struct FlowIndex_t*		FreeNext;			// next in free list

} FlowIndex_t;

//---------------------------------------------------------------------------------------------
// command line parameters, see main.c for descriptions
extern bool				g_IsJSONPacket;
extern bool				g_IsJSONFlow;

extern s64				g_FlowSampleRate;
extern bool				g_IsFlowNULL;

extern bool				g_FlowTopNEnable;
extern u32				g_FlowTopNMax;

extern u8				g_FlowTopNMac;
extern u8				g_FlowTopNsMac[MAX_TOPN_MAC][6];
extern u8				g_FlowTopNdMac[MAX_TOPN_MAC][6];

extern bool				g_Output_Histogram;
extern FILE*			g_Output_Histogram_FP;

extern u8 				g_CaptureName[256];
extern u8				g_DeviceName[128];

extern bool				g_Verbose;

extern bool				g_Output_NULL;
extern bool				g_Output_STDOUT;
extern u8*				g_Output_PipeName;

extern bool			g_Output_TCP_STDOUT;
extern u8*				g_Output_TCP_PipeName;

extern u8*				g_FlowIndexRollRead;
extern u8*				g_FlowIndexRollWrite;

extern u8				g_InstanceID;
extern u8				g_InstanceMax;

extern bool				g_ICMPOverwrite;

//---------------------------------------------------------------------------------------------
// static
static volatile bool			s_Exit = false;

static u32						s_FlowCntSnapshotLast = 0;				// last total flows in the last snapshot
static u64						s_PktCntSnapshotLast = 0;				// last total number of packets in the snapshot 

static u64						s_FlowMax			= 0;				// total max flows per snapshot. via commandline

static u32						s_FlowIndexMax		= 16;
static u32						s_FlowIndexSub		= 0;				// number of sub slots, one per CPU worker 
static FlowIndex_t				s_FlowIndex[1024];
static u32						s_FlowIndexFreeLock	= 0;				// lock to access
static FlowIndex_t*				s_FlowIndexFree		= NULL;				// free list

static u64						s_FlowCntTotal		= 0;				// total number of active flows
static u64						s_PktCntTotal		= 0;				// total number of packets processed 
static u64						s_FlowSampleTSLast	= 0;				// last time the flow was sampled 

static u32						s_PacketBufferMax	= 1024;				// max number of inflight packets
static PacketBuffer_t			s_PacketBufferList[1024];				// list of header structs for each buffer^
static volatile PacketBuffer_t*	s_PacketBuffer		= NULL;				// linked list of free packet buffers
static u32						s_PacketBufferLock	= 0;

static u32						s_DecodeCPUActive 	= 0;				// total number of active decode threads
static pthread_t   				s_DecodeThread[128];						// worker decode thread list
static u64						s_DecodeThreadTSCTop[128];				// total cycles
static u64						s_DecodeThreadTSCDecode[128];			// total cycles for decoding
static u64						s_DecodeThreadTSCInsert[128];			// cycles spend in hash table lookup 
static u64						s_DecodeThreadTSCHash[128];				// cycles spend hashing the flow 
static u64						s_DecodeThreadTSCOutput[128];			// cycles spent in output logic 
static u64						s_DecodeThreadTSCOStall[128];			// cycles spent waiting for an FlowIndex alloc 
static u64						s_DecodeThreadTSCMerge[128];			// cycles spent merging multiple flow indexs 
static u64						s_DecodeThreadTSCWrite[128];			// cycles spent serialzing the json output sprintf dominated 
static u64						s_DecodeThreadTSCOut[128];				// cycles spent on output buffer adding 
static u64						s_DecodeThreadTSCReset[128];			// cycles spent reseting structures 
static u64						s_DecodeThreadTSCWorker[128];			// cycles spent waiting for workers to complete 

static volatile u64				s_DecodeQueuePut 	= 0;				// put/get processing queue
static volatile u64				s_DecodeQueueGet 	= 0;
static u64						s_DecodeQueueMax 	= 1024;
static u64						s_DecodeQueueMsk 	= 1023;
static volatile PacketBuffer_t*	s_DecodeQueue[1024];					// list of packets pending processing

static struct Output_t*			s_Output			= NULL;				// output module
static struct Output_t*			s_TCP_Output		= NULL;				// TCP event output module

static u64						s_PacketQueueCnt	= 0;
static u64						s_PacketDecodeCnt	= 0;

static u32						s_PacketSizeHistoBin = 32;				// size divide amount 
static u32						s_PacketSizeHistoMax = 1024;			// max index 
static u32						s_PacketSizeHisto[128][1024];			// packet size histogram per snaphot

static u32						s_FlowDepthHistoBin = 1;				// size divide amount 
static u32						s_FlowDepthHistoMax = 128;				// max index 
static u32						s_FlowDepthHisto[128][128];				// monitors the depth of each flow,
																		// eg. are all the flows a single packt in the snapshot
																		// or is it 1 flow with the majority of packets						
static u32						s_FlowDepthHistoCnt[128];				// number of updates
static float 					s_FlowDepthMedian = 0;					// calculated median depth of each flow entry

static u64						s_FlowPreloadTS		= 0;				// timestamp of preloaded flow snapshot 
static u32						s_FlowPreloadCnt	= 0;				// number of preloaded flows
static FlowRecord_t*			s_FlowPreload		= NULL;				// preloaded flow data


//---------------------------------------------------------------------------------------------
// generate a 20bit hash index 
static u32 HashIndex(u32* SHA1)
{
	u8* Data8 = (u8*)SHA1;

	// FNV1a 80b hash 
	const u32 Prime  = 0x01000193; //   16777619
	const u32  Seed  = 0x811C9DC5; // 2166136261

	u32 Hash = Seed;
	Hash = ((u32)Data8[ 0] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 1] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 2] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 3] ^ Hash) * Prime;

	Hash = ((u32)Data8[ 4] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 5] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 6] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 7] ^ Hash) * Prime;

	Hash = ((u32)Data8[ 8] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 9] ^ Hash) * Prime;
	Hash = ((u32)Data8[10] ^ Hash) * Prime;
	Hash = ((u32)Data8[11] ^ Hash) * Prime;

	Hash = ((u32)Data8[12] ^ Hash) * Prime;
	Hash = ((u32)Data8[13] ^ Hash) * Prime;
	Hash = ((u32)Data8[14] ^ Hash) * Prime;
	Hash = ((u32)Data8[15] ^ Hash) * Prime;

	Hash = ((u32)Data8[16] ^ Hash) * Prime;
	Hash = ((u32)Data8[17] ^ Hash) * Prime;
	Hash = ((u32)Data8[18] ^ Hash) * Prime;
	Hash = ((u32)Data8[19] ^ Hash) * Prime;

	// reduce down to 20bits for set/way index
	return (Hash & 0x000fffff) ^ (Hash >> 20);
}

//---------------------------------------------------------------------------------------------
// Generate a deterministic 5-tuple struct that can then be hashed
s8 FlowPktToTCPFullDup(FlowRecord_t* FlowPkt, TCPFullDup_t* TCPFullDup)
{
	TCPFullDup->IPProto = FlowPkt->IPProto;

	// Sort FlowPkt's IP src-dst deterministically and set to TCPFullDup's A/B
	// accordingly
	s8 cmp = memcmp(FlowPkt->IPSrc, FlowPkt->IPDst, sizeof(FlowPkt->IPSrc));
	if (cmp == 0)
	{
		cmp = FlowPkt->PortSrc < FlowPkt->PortDst ? 1 : -1;
	}

	if (cmp > 0)
	{
		memcpy(TCPFullDup->IP_A, FlowPkt->IPSrc, sizeof(FlowPkt->IPSrc));
		memcpy(TCPFullDup->IP_B, FlowPkt->IPDst, sizeof(FlowPkt->IPDst));

		TCPFullDup->PortA = FlowPkt->PortSrc;
		TCPFullDup->PortB = FlowPkt->PortDst;
	}
	else
	{
		memcpy(TCPFullDup->IP_A, FlowPkt->IPDst, sizeof(FlowPkt->IPDst));
		memcpy(TCPFullDup->IP_B, FlowPkt->IPSrc, sizeof(FlowPkt->IPSrc));

		TCPFullDup->PortA = FlowPkt->PortDst;
		TCPFullDup->PortB = FlowPkt->PortSrc;
	}

	return cmp;
}

//---------------------------------------------------------------------------------------------

static FlowRecord_t* FlowAlloc(FlowIndex_t* FlowIndex, FlowRecord_t* F)
{
	assert(FlowIndex->FlowCntSnapshot < FlowIndex->FlowMax);

	FlowRecord_t* Flow = &FlowIndex->FlowList[ FlowIndex->FlowCntSnapshot++ ]; 

	// this resets the TotalPkt/Byte counters  
	memset(Flow, 0, sizeof(FlowRecord_t) );

	// copy flow values, leaving the counters reset at zero 
	memcpy(Flow, F, offsetof(FlowRecord_t, pad));

	// copy values that are part of the flow but not included with the hash
	Flow->MPLS0 	= F->MPLS0;
	Flow->MPLStc0 	= F->MPLStc0;

	// copy per packet state
	Flow->TCPLength = F->TCPLength;

	return Flow;
}

//---------------------------------------------------------------------------------------------
// free a flow index 
static void FlowIndexFree(FlowIndex_t* FlowIndexRoot)
{
	for (int i=0; i < s_FlowIndexSub; i++)
	{
		FlowIndex_t* FlowIndex = FlowIndexRoot + i;

		if (!FlowIndex->IsUse)
		{
			printf("ERRROR: IndexFree: %p %i InUse:%i\n", FlowIndexRoot, i, FlowIndex->IsUse);
		}

		// as running memset(FlowIndex->FlowHash) is expensive
		// just bump the counter to invalidate previous values
		FlowIndex->FrameID++;
		
		// when the counter wraps force a full clear 
		// ensures 100% there is no FrameID collisions with stale FlowHashFrameID values 
		if (FlowIndex->FrameID == 0)
		{
			memset(FlowIndex->FlowHash, 0, sizeof(u32) * (2 << 20) );
		}
		FlowIndex->FlowCntSnapshot = 0;

		FlowIndex->PktBlockCnt 	= 0;
		FlowIndex->PktBlockMax 	= 0;

		FlowIndex->IsUse 		= false;
	}

	// append the root FlowIndex into the alloc list
	sync_lock(&s_FlowIndexFreeLock, 100);
	{
		// check index is not already in free list
		bool IsError = false;
		FlowIndex_t* I = s_FlowIndexFree;
		while (I)
		{
			if (I == FlowIndexRoot)
			{
				printf("***ERROR** double entry\n");
				IsError = true;
				break;
			}	
			I = I->FreeNext;
		}

		if (!IsError)
		{
			FlowIndexRoot->FreeNext = s_FlowIndexFree;
			s_FlowIndexFree			= FlowIndexRoot;
		}
	}
	sync_unlock(&s_FlowIndexFreeLock);
}

// allocate a root flow index
static FlowIndex_t* FlowIndexAlloc(void)
{
	FlowIndex_t* F = NULL;
	while (!F)
	{
		sync_lock(&s_FlowIndexFreeLock, 100);
		{
			F = s_FlowIndexFree;
			if (F)
			{
				s_FlowIndexFree = F->FreeNext;
			}
		}
		sync_unlock(&s_FlowIndexFreeLock);

		// update SHM Ring HB 
		g_BusyWaitFn();
	}
	for (int i=0; i < s_FlowIndexSub; i++)
	{
		(F+i)->IsUse = true;
	}

	return F;
}

//---------------------------------------------------------------------------------------------
// returns the flow entry or creates one in the index
static FlowRecord_t* FlowAdd(FlowIndex_t* FlowIndex, FlowRecord_t* FlowPkt, u32* SHA1Half)
{
	//u64 TSC0 = rdtsc();

	bool IsFlowNew = false;
	FlowRecord_t* F = NULL;

	u32 Index = HashIndex(SHA1Half);

	// first record ?
	if (FlowIndex->FlowHashFrameID[ Index ] != FlowIndex->FrameID)
	{
		F = FlowAlloc(FlowIndex, FlowPkt);

		F->SHA1Half[0] = SHA1Half[0];
		F->SHA1Half[1] = SHA1Half[1];
		F->SHA1Half[2] = SHA1Half[2];
		F->SHA1Half[3] = SHA1Half[3];
		F->SHA1Half[4] = SHA1Half[4];

		F->Next		= NULL;
		F->Prev		= NULL;

		FlowIndex->FlowHash[Index] = F - FlowIndex->FlowList;

		FlowIndex->FlowHashFrameID[ Index ] = FlowIndex->FrameID;

		IsFlowNew = true;
	}
	else
	{
		F = FlowIndex->FlowList + FlowIndex->FlowHash[ Index ];

		// iterate in search of the flow
		u32 Timeout = 0; 
		FlowRecord_t* FPrev = NULL;
		while (F)
		{
			bool IsHit = true;

			IsHit &= (F->SHA1Half[0] == SHA1Half[0]);
			IsHit &= (F->SHA1Half[1] == SHA1Half[1]);
			IsHit &= (F->SHA1Half[2] == SHA1Half[2]);
			IsHit &= (F->SHA1Half[3] == SHA1Half[3]);
			IsHit &= (F->SHA1Half[4] == SHA1Half[4]);

			if (IsHit)
			{
				break;
			}

			FPrev = F;
			F = F->Next;

			assert(Timeout++ < 1e6);
		}

		// new flow
		if (!F)
		{
			F = FlowAlloc(FlowIndex, FlowPkt);

			F->SHA1Half[0] = SHA1Half[0];
			F->SHA1Half[1] = SHA1Half[1];
			F->SHA1Half[2] = SHA1Half[2];
			F->SHA1Half[3] = SHA1Half[3];
			F->SHA1Half[4] = SHA1Half[4];

			F->Next		= NULL;
			F->Prev		= NULL;

			FPrev->Next = F;
			F->Prev		= FPrev;

			IsFlowNew	= true;
		}
	}

	// Copy properties that FlowAlloc skips
	F->SHA1Full[0] = FlowPkt->SHA1Full[0];
	F->SHA1Full[1] = FlowPkt->SHA1Full[1];
	F->SHA1Full[2] = FlowPkt->SHA1Full[2];
	F->SHA1Full[3] = FlowPkt->SHA1Full[3];
	F->SHA1Full[4] = FlowPkt->SHA1Full[4];
	F->TCPEventCount += FlowPkt->TCPEventCount;

	//u64 TSC1 = rdtsc();
	//s_DecodeThreadTSCInsert[CPUID] += TSC1 - TSC0;

	return F;
}

//---------------------------------------------------------------------------------------------
// assumption is this is mutually exclusive per FlowIndex
static void FlowInsert(u32 CPUID, FlowIndex_t* FlowIndex, FlowRecord_t* FlowPkt, u32* SHA1, u32 Length, u64 TS)
{
	// create/fetch the flow entry
	FlowRecord_t* F = FlowAdd(FlowIndex, FlowPkt, SHA1);
	assert(F != NULL);

	if (g_Output_Histogram)
	{
		s64 dTS = (F->LastTS == 0) ? 0 : (TS - F->LastTS);
		PktInfo_Insert(&F->PktInfoB, Length, dTS);
	}

	// update flow stats
	F->TotalPkt		+= 1;
	F->TotalByte	+= Length;
	F->FirstTS		= (F->FirstTS == 0) ? TS : F->FirstTS;
	F->LastTS		=  TS;

	F->TotalFCS		+= FlowPkt->TotalFCS;

	// potential IP4 fragmentation counts 
	F->IP4FragCnt	+= FlowPkt->IP4FragCnt; 

	// update tcp stats
	if (F->IPProto == IPv4_PROTO_TCP)
	{
		// update TCP Flag counts
		TCPHeader_t* TCP 	= &FlowPkt->TCPHeader; 

		u16 TCPFlags 		= swap16(TCP->Flags);
		F->TCPFINCnt		+= (TCP_FLAG_FIN(TCPFlags) != 0);

		F->TCPSYNCnt		+= (TCP_FLAG_SYN(TCPFlags) != 0) && (TCP_FLAG_ACK(TCPFlags) == 0);
		F->TCPSYNACKCnt		+= (TCP_FLAG_SYN(TCPFlags) != 0) && (TCP_FLAG_ACK(TCPFlags) != 0);
		F->TCPSYNSACKCnt	+= (TCP_FLAG_SYN(TCPFlags) != 0) && (FlowPkt->TCPIsSACK & TCP_SACK_ENABLE);

		F->TCPRSTCnt		+= (TCP_FLAG_RST(TCPFlags) != 0);
		F->TCPPSHCnt		+= (TCP_FLAG_PSH(TCPFlags) != 0);
		F->TCPACKCnt		+= (TCP_FLAG_ACK(TCPFlags) != 0);


		// check for re-transmits
		// works by checking for duplicate 0 payload acks
		// of an ack no thats already been seen. e.g. tcp fast re-transmit request
		// https://en.wikipedia.org/wiki/TCP_congestion_control#Fast_retransmit
		// 
		// 2018/12/04: SACK traffic messes this up
/*
		if (TCP_FLAG_ACK(TCPFlags))
		{
			u32 TCPAckNo	= swap32(TCP->AckNo);
			if ((FlowPkt->TCPLength == 0) && (F->TCPAckNo == TCPAckNo))
			{
				// if its not a SACK
				if (!FlowPkt->TCPIsSACK)
				{
					F->TCPSACKCnt	+= 1; 
				}
				else
				{
					F->TCPACKDupCnt	+= 1; 
				}
			}
			F->TCPAckNo = TCPAckNo;
		}
*/

		// count SACKs per flow
		if (FlowPkt->TCPIsSACK & TCP_SACK_OPTION) F->TCPSACKCnt	+= 1; 

		// RST pkt window size is always 0, and ignore SYN packets for zero window calcs
		if ((TCP_FLAG_RST(TCPFlags) == 0) && (TCP_FLAG_SYN(TCPFlags) == 0))
		{
			u32 TCPWindow = swap16(TCP->Window);
			if (TCPWindow == 0)
			{
				F->TCPWindowZero++;
			}
		}
	}

	// ICMP may have overwritten the IP protocol so always update
	F->ICMPUnreach			+= FlowPkt->ICMPUnreach;
	F->ICMPTimeout			+= FlowPkt->ICMPTimeout;
	F->ICMPOverwrite		+= FlowPkt->ICMPOverwrite;
	/*
	if (F->ICMPOverwrite > 0)
	{
		if ((F->ICMPSrc.IP4 != 0) && (F->ICMPSrc.IP4 != FlowPkt->ICMPSrc.IP4))
		{
			printf("missmatch (%i) %08x %08x\n", F->ICMPOverwrite, F->ICMPSrc.IP4, FlowPkt->ICMPSrc.IP4);
		}
	}
	*/
	F->ICMPSrc					= FlowPkt->ICMPSrc;
}

//---------------------------------------------------------------------------------------------
// write a flow record out as a JSON file
// this is designed for ES bulk data upload using the 
// mappings.json file as the index 
static u32 FlowDump(u8* OutputStr, u64 TS, FlowRecord_t* Flow, u32 FlowID, u32 FlowTotal) 
{
	u8* Output 		= OutputStr;


	// set snapshot timestamp
	Flow->SnapshotTS = TS;

	Flow->FlowInstance 	= 0;
	Flow->FlowNo 		= FlowID;
	Flow->TotalFlows 	= FlowTotal;

	// global isntance settings
	Flow->InstanceID 	= g_InstanceID;
	Flow->InstanceMax 	= g_InstanceMax;

	// pipe output
	if (g_Output_PipeName != NULL)
	{
		memcpy(Output, Flow, sizeof(FlowRecord_t) );
		return sizeof(FlowRecord_t);
	}	
	else if (g_Output_STDOUT)
	{
		// ES header for bulk upload
		Output += sprintf(Output, "{\"index\":{\"_index\":\"%s\",\"_type\":\"flow_record\",\"_score\":null}}\n", g_CaptureName);

		// as its multi threaded FormatTS can not be used
		u8 TStr[128];
		FormatTSStr(TStr, TS);

		// actual payload
		Output += sprintf(Output, "{\"timestamp\":%f,\"TS\":\"%s\",\"FlowCnt\":%lli,\"Device\":\"%s\"", TS/1e6, TStr, FlowID, g_DeviceName);

		// print flow info
		Output += sprintf(Output, ",\"hashHalf\":\"%08x%08x%08x%08x%08x\"",	Flow->SHA1Half[0],
																			Flow->SHA1Half[1],
																			Flow->SHA1Half[2],
																			Flow->SHA1Half[3],
																			Flow->SHA1Half[4]);

		if (Flow->EtherProto == ETHER_PROTO_IPV4)
		{
			Output += sprintf(Output,
							  ",\"hashFull\":\"%08x%08x%08x%08x%08x\"",
							  Flow->SHA1Full[0],
							  Flow->SHA1Full[1],
							  Flow->SHA1Full[2],
							  Flow->SHA1Full[3],
							  Flow->SHA1Full[4]);
		}

		Output += sprintf(Output, ",\"MACSrc\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"MACDst\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",

															Flow->EtherSrc[0],
															Flow->EtherSrc[1],
															Flow->EtherSrc[2],
															Flow->EtherSrc[3],
															Flow->EtherSrc[4],
															Flow->EtherSrc[5],

															Flow->EtherDst[0],
															Flow->EtherDst[1],
															Flow->EtherDst[2],
															Flow->EtherDst[3],
															Flow->EtherDst[4],
															Flow->EtherDst[5]
		);

		// output human readable Ether protocol info
		u8 MACProto[128];
		switch (Flow->EtherProto)
		{
		case ETHER_PROTO_ARP:
			strcpy(MACProto, "ARP");
			break;
		case ETHER_PROTO_IPV4:
			strcpy(MACProto, "IPv4");
			break;
		case ETHER_PROTO_IPV6:
			strcpy(MACProto, "IPv6");
			break;
		case ETHER_PROTO_VLAN:
			strcpy(MACProto, "VLAN");
			break;
		case ETHER_PROTO_VNTAG:
			strcpy(MACProto, "VNTAG");
			break;
		case ETHER_PROTO_MPLS:
			strcpy(MACProto, "MPLS");
			break;
		default:
			sprintf(MACProto, "%04x", Flow->EtherProto);
			break;
		}
		Output += sprintf(Output, ",\"MACProto\":\"%s\"", MACProto); 

		// print VLAN is valid
		if (Flow->VLAN[0] != 0xffff)
		{
			Output += sprintf(Output, ",\"VLAN.0\":%i",  Flow->VLAN[0]);
		}
		if (Flow->VLAN[1] != 0xffff)
		{
			Output += sprintf(Output, ",\"VLAN.1\":%i",  Flow->VLAN[1]);
		}

		// print MPLS info
		if (Flow->MPLS0)
		{
			Output += sprintf(Output, ",\"MPLS.0.Label\":%i, \"MPLS.0.TC\":%i",  Flow->MPLS0, Flow->MPLStc0);
		}
		if (Flow->MPLS1)
		{
			Output += sprintf(Output, ",\"MPLS.1.Label\":%i, \"MPLS.1.TC\":%i",  Flow->MPLS1, Flow->MPLStc1);
		}
		if (Flow->MPLS2)
		{
			Output += sprintf(Output, ",\"MPLS.2.Label\":%i, \"MPLS.2.TC\":%i",  Flow->MPLS2, Flow->MPLStc2);
		}


		// IPv4 proto info
		if (Flow->EtherProto ==  ETHER_PROTO_IPV4)
		{
			Output += sprintf(Output, ",\"IPv4.Src\":\"%i.%i.%i.%i\",\"IPv4.Dst\":\"%i.%i.%i.%i\" ",
												Flow->IPSrc[0],
												Flow->IPSrc[1],
												Flow->IPSrc[2],
												Flow->IPSrc[3],

												Flow->IPDst[0],
												Flow->IPDst[1],
												Flow->IPDst[2],
												Flow->IPDst[3]
			);

			if (Flow->IP4FragCnt != 0)
			{
				Output += sprintf(Output, ",\"IPv4.Fragment\":\"%i\"", Flow->IP4FragCnt);
			}

			// convert to readable names for common protocols 
			u8 IPProto[128];
			switch (Flow->IPProto) 
			{
			case IPv4_PROTO_UDP:	strcpy(IPProto, "UDP");		break;
			case IPv4_PROTO_TCP:	strcpy(IPProto, "TCP");		break;
			case IPv4_PROTO_IGMP:	strcpy(IPProto, "IGMP"); 	break;
			case IPv4_PROTO_ICMP:	strcpy(IPProto, "ICMP"); 	break;
			case IPv4_PROTO_GRE:	strcpy(IPProto, "GRE"); 	break;
			case IPv4_PROTO_VRRP:	strcpy(IPProto, "VRRP"); 	break;
			default:
				sprintf(IPProto, "%02x", Flow->IPProto);
				break;
			}
			Output += sprintf(Output, ",\"IPv4.Proto\":\"%s\"", IPProto);

			// per protocol info
			switch (Flow->IPProto)
			{
			case IPv4_PROTO_UDP:
			{
				Output += sprintf(Output, ",\"UDP.Port.Src\":%i,\"UDP.Port.Dst\":%i",
													Flow->PortSrc,
													Flow->PortDst	
				);
			}
			break;

			case IPv4_PROTO_TCP:
			{
				Output += sprintf(Output,",\"TCP.FIN\":%i,\"TCP.SYN\":%i,\"TCP.RST\":%i,\"TCP.PSH\":%i,\"TCP.ACK\":%i,\"TCP.IsSACK\":%i,\"TCP.WinZero\":%i,\"TCP.SACK\":%i",
						Flow->TCPFINCnt,
						Flow->TCPSYNCnt,
						Flow->TCPRSTCnt,
						Flow->TCPPSHCnt,
						Flow->TCPACKCnt,

						Flow->TCPIsSACK,
						Flow->TCPWindowZero,
						Flow->TCPSACKCnt
				);
				Output += sprintf(Output, ",\"TCP.Port.Src\":%i,\"TCP.Port.Dst\":%i",
											Flow->PortSrc,
											Flow->PortDst	
				);
			}
			break;
			}

			if (Flow->ICMPOverwrite)
			{

				Output += sprintf(Output,",\"ICMP.Unreach\":%i,\"ICMP.Timeout\":%i,\"ICMP.Overwrite\":%i,\"ICMP.srcIP\":\"%i.%i.%i.%i\"",
						Flow->ICMPUnreach,
						Flow->ICMPTimeout,
						Flow->ICMPOverwrite,
						Flow->ICMPSrc.IP[0],
						Flow->ICMPSrc.IP[1],
						Flow->ICMPSrc.IP[2],
						Flow->ICMPSrc.IP[3]
				);
			}
		}

		Output += sprintf(Output, ",\"TotalPkt\":%lli,\"TotalByte\":%lli,\"TotalBits\":%lli",
										Flow->TotalPkt,
										Flow->TotalByte,
										Flow->TotalByte*8ULL
		);

		if (g_Output_TCP_STDOUT)
		{
			Output += sprintf(Output, ",\"TCPEventCount\":%llu", Flow->TCPEventCount);
		}
		Output += sprintf(Output, "}\n");

		return Output - OutputStr;
	}
	// null output
	else
	{
		return 0;
	}
}

//---------------------------------------------------------------------------------------------
// merges mutliple flow entries into a single index
// as each CPU flow list gets merged into a single list 
static void FlowMerge(FlowIndex_t* IndexOut, FlowIndex_t* IndexRoot, u32 IndexCnt)
{
	for (int CPU=0; CPU < IndexCnt; CPU++)
	{
		FlowIndex_t* Source = IndexRoot + CPU; 
		if (Source == IndexOut) continue;

		for (int i=0; i < Source->FlowCntSnapshot; i++)
		{
			// source flow to merge from
			FlowRecord_t* Flow = &Source->FlowList[i];

			// merge into a single FlowIndex 
			FlowRecord_t* F = FlowAdd(IndexOut, Flow, Flow->SHA1Half);

			F->TotalPkt 	+= Flow->TotalPkt;
			F->TotalByte 	+= Flow->TotalByte;
			F->FirstTS 		= min64ne0(F->FirstTS, Flow->FirstTS);
			F->LastTS 		= max64(F->LastTS, Flow->LastTS);
			F->TotalFCS 	+= Flow->TotalFCS;	

			if (F->PktInfoB)
			{
				PacketInfoBulk_t *last	= F->PktInfoB;

				for (; last->Next != NULL; last = last->Next);

				last->Next	= Flow->PktInfoB;
			}
			else
				F->PktInfoB = Flow->PktInfoB;

			Flow->PktInfoB 		= NULL;

			F->IP4FragCnt		+= Flow->IP4FragCnt; 

			// TCP stats
			if (F->IPProto == IPv4_PROTO_TCP)
			{
				F->TCPFINCnt		+= Flow->TCPFINCnt; 
				F->TCPSYNCnt		+= Flow->TCPSYNCnt; 
				F->TCPSYNACKCnt		+= Flow->TCPSYNACKCnt; 
				F->TCPSYNSACKCnt	+= Flow->TCPSYNSACKCnt; 
				F->TCPRSTCnt		+= Flow->TCPRSTCnt; 
				F->TCPPSHCnt		+= Flow->TCPPSHCnt; 
				F->TCPACKCnt		+= Flow->TCPACKCnt; 
				F->TCPSACKCnt		+= Flow->TCPSACKCnt; 
				F->TCPWindowZero 	+= Flow->TCPWindowZero; 
			}

			// ICMP may have overwritten protocol info so always add them
			F->ICMPUnreach			+= Flow->ICMPUnreach;
			F->ICMPTimeout			+= Flow->ICMPTimeout;
			F->ICMPOverwrite		+= Flow->ICMPOverwrite;
			F->ICMPSrc				= Flow->ICMPSrc;
		}
	}
}

// merge into preloaded flowsa (once per startup)
static void FlowMergePreload(FlowIndex_t* IndexOut)
{
	printf("preload merge %i\n", s_FlowPreloadCnt);
	for (int i=0; i < s_FlowPreloadCnt; i++)
	{
		// source flow to merge from
		FlowRecord_t* Flow = &s_FlowPreload[i];

		// merge into a single FlowIndex 
		FlowRecord_t* F = FlowAdd(IndexOut, Flow, Flow->SHA1Half);

		F->TotalPkt 	+= Flow->TotalPkt;
		F->TotalByte 	+= Flow->TotalByte;
		F->FirstTS 		= min64ne0(F->FirstTS, Flow->FirstTS);
		F->LastTS 		= max64(F->LastTS, Flow->LastTS);
		F->TotalFCS		+= Flow->TotalFCS;	
		F->IP4FragCnt	+= Flow->IP4FragCnt; 

		F->ICMPUnreach		+= Flow->ICMPUnreach; 
		F->ICMPTimeout		+= Flow->ICMPTimeout; 
		F->ICMPOverwrite	+= Flow->ICMPOverwrite; 

		// TCP stats
		if (F->IPProto == IPv4_PROTO_TCP)
		{
			F->TCPFINCnt		+= Flow->TCPFINCnt; 
			F->TCPSYNCnt		+= Flow->TCPSYNCnt; 
			F->TCPSYNACKCnt		+= Flow->TCPSYNACKCnt; 
			F->TCPSYNSACKCnt	+= Flow->TCPSYNSACKCnt; 
			F->TCPRSTCnt		+= Flow->TCPRSTCnt; 
			F->TCPPSHCnt		+= Flow->TCPPSHCnt; 
			F->TCPACKCnt		+= Flow->TCPACKCnt; 
			F->TCPSACKCnt		+= Flow->TCPSACKCnt; 
			F->TCPWindowZero 	+= Flow->TCPWindowZero; 
		}
	}
}

static int cmp_long(const void* a, const void* b)
{
	const u64* a64 = (const u64*)a;
	const u64* b64 = (const u64*)b;

	if (a64[1] == b64[1])
	{
		return (a64[2] < b64[2]);
	}
	else
	{
		return (a64[1] < b64[1]);
	}
}

//---------------------------------------------------------------------------------------------
// sort the flow list, and output the top N by total bytes 
static u32 FlowTopN(u32* SortList, FlowIndex_t* FlowIndex, u32 FlowMax, u8 *sMac, u8 *dMac)
{
	u64	j			= 0;
	u64	MinByte		= (u64)-1;
	u64	MaxByte 	= (u64)0;

	// reset sorted output
	u32 SortListPos = 0;

	//u64 TSC0 = rdtsc();

	{
		// build array for qsort to work on
		u64* List = (u64*)SortList;
		for (int i=0; i < FlowIndex->FlowCntSnapshot; i++)
		{
			FlowRecord_t* F = &FlowIndex->FlowList[i];
			if (!sMac || !dMac)
			{
				List[j*3 + 0] = i;
				List[j*3 + 1] = F->TotalByte;
				List[j*3 + 2] = F->SHA1Half[4];
				j++;
			}
			else if (MAC_CMP(FlowIndex->FlowList[i].EtherDst, dMac) &&
					MAC_CMP(FlowIndex->FlowList[i].EtherSrc, sMac))
			{
				List[j*3 + 0] = i;
				List[j*3 + 1] = F->TotalByte;
				List[j*3 + 2] = F->SHA1Half[4];
				j++;
			}

			//fprintf(stderr, "i: %d TotalByte: %llu SRC:" MAC_FMT " DEST: " MAC_FMT "\n", i, FlowIndex->FlowList[i].TotalByte,
			//		MAC_PRNT_S(&FlowIndex->FlowList[i]), MAC_PRNT_D(&FlowIndex->FlowList[i]));
		}

		// sort all flows by total bytes
		qsort(List, j, 3*sizeof(u64), cmp_long);

		// max number of flows
		SortListPos = min64(FlowMax, j);

		// merge into a single list again
		// works as List is awlays larger writing to a smaller(u32) list
		// so can be done in-place
		for (int i=0; i < SortListPos; i++)
		{
			SortList[i] = List[i*3 + 0];
		}
	}

	//u64 TSC1 = rdtsc();
	//fprintf(stderr, "flow count: %llu j: %llu FlowMax: %u SortListPos: %u\n", FlowIndex->FlowCntSnapshot, j, FlowMax, SortListPos); 
	//fprintf(stderr, "Took: %.6f ms %.6f ms\n", tsc2ns(TSC1 - TSC0)/1e6, tsc2ns(TSC2 - TSC1)/1e6 ); 

	/*
	// validate the sort
	for (int i=0; i < SortListPos-1; i++)
	{
		u32 Index0 = SortList[i+0];
		u32 Index1 = SortList[i+1];

		FlowRecord_t* F0 = &FlowIndex->FlowList[Index0];
		FlowRecord_t* F1 = &FlowIndex->FlowList[Index1];
		assert(F0->TotalByte >= F1->TotalByte);
	}
	*/

	return SortListPos;
}

//---------------------------------------------------------------------------------------------
//
// parse a packet and generate a flow record 
//
void DecodePacket(	u32 CPUID,
					struct Output_t* Out, 
					u64 SnapshotTS,
					FMADPacket_t* PktHeader, 
					FlowIndex_t* FlowIndex)
{
	FlowRecord_t	sFlow;	
	FlowRecord_t*	FlowPkt = &sFlow;	
	memset(FlowPkt, 0, sizeof(FlowRecord_t));

	// assume single packet flow
	FlowPkt->TotalPkt	 	= 1;
	FlowPkt->TotalByte 		= PktHeader->LengthWire;
	FlowPkt->TotalFCS		+= (PktHeader->Flag & FMAD_PACKET_FLAG_FCS) ? 1 : 0;

	// ether header info
	fEther_t* Ether 		= (fEther_t*)(PktHeader + 1);	
	u8* Payload 			= (u8*)(Ether + 1);
	u16 EtherProto 			= swap16(Ether->Proto);

	// Used by TCPEventDump
	u32 TCPWindowScale = 0;

	FlowPkt->EtherProto		= EtherProto;
	FlowPkt->EtherSrc[0]	= Ether->Src[0];
	FlowPkt->EtherSrc[1]	= Ether->Src[1];
	FlowPkt->EtherSrc[2]	= Ether->Src[2];
	FlowPkt->EtherSrc[3]	= Ether->Src[3];
	FlowPkt->EtherSrc[4]	= Ether->Src[4];
	FlowPkt->EtherSrc[5]	= Ether->Src[5];

	FlowPkt->EtherDst[0]	= Ether->Dst[0];
	FlowPkt->EtherDst[1]	= Ether->Dst[1];
	FlowPkt->EtherDst[2]	= Ether->Dst[2];
	FlowPkt->EtherDst[3]	= Ether->Dst[3];
	FlowPkt->EtherDst[4]	= Ether->Dst[4];
	FlowPkt->EtherDst[5]	= Ether->Dst[5];

	// VLAN decoder. as VLAN = 0 is not uncommon, use a non 0 value
	// to determin if vlan is enabled or disabled
	FlowPkt->VLAN[0]		= 0xffff; 
	FlowPkt->VLAN[1]		= 0xffff; 
	FlowPkt->VLAN[2]		= 0xffff; 
	FlowPkt->VLAN[3]		= 0xffff; 

	if (EtherProto == ETHER_PROTO_VLAN)
	{
		VLANTag_t* Header 	= (VLANTag_t*)(Ether+1);
		u16* Proto 			= (u16*)(Header + 1);

		// update to the acutal proto / ipv4 header
		EtherProto 			= swap16(Proto[0]);
		Payload 			= (u8*)(Proto + 1);

		// first vlan tag
		FlowPkt->VLAN[0]	= VLANTag_ID(Header);

		// VNTag unpack (BME) 
		if (EtherProto == ETHER_PROTO_VNTAG)
		{
			VNTag_t* Header = (VNTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);
		}

		// is it double tagged ? 
		if (EtherProto == ETHER_PROTO_VLAN)
		{
			Header 			= (VLANTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);

			// 2nd vlan tag
			FlowPkt->VLAN[1]		= VLANTag_ID(Header);
		}
	}

	// MPLS decoder	
	if (EtherProto == ETHER_PROTO_MPLS)
	{
		MPLSHeader_t* MPLS = (MPLSHeader_t*)(Payload);

		u32 MPLSDepth = 0;

		// first MPLS 
		FlowPkt->MPLS0		= MPLS_LABEL(MPLS);
		FlowPkt->MPLStc0	= MPLS->TC;

		// for now only process outer tag
		// assume there is a sane limint on the encapsulation count
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// seccond 
			FlowPkt->MPLS1		= MPLS_LABEL(MPLS);
			FlowPkt->MPLStc1	= MPLS->TC;
		}
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// third 
			FlowPkt->MPLS2		= MPLS_LABEL(MPLS);
			FlowPkt->MPLStc2	= MPLS->TC;
		}
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// fourth 
			FlowPkt->MPLS3		= MPLS_LABEL(MPLS);
			FlowPkt->MPLStc3	= MPLS->TC;
		}

		// update to next header
		if (MPLS->BOS)
		{
			EtherProto = ETHER_PROTO_IPV4;
			Payload = (u8*)(MPLS + 1);
		}
	}

	// update final ethernet protocol
	FlowPkt->EtherProto	= EtherProto;

	// ipv4 info
	if (EtherProto == ETHER_PROTO_IPV4)
	{
		IP4Header_t* IP4 = (IP4Header_t*)Payload;
		FlowPkt->IPSrc[0] = IP4->Src.IP[0];	
		FlowPkt->IPSrc[1] = IP4->Src.IP[1];	
		FlowPkt->IPSrc[2] = IP4->Src.IP[2];	
		FlowPkt->IPSrc[3] = IP4->Src.IP[3];	

		FlowPkt->IPDst[0] = IP4->Dst.IP[0];	
		FlowPkt->IPDst[1] = IP4->Dst.IP[1];	
		FlowPkt->IPDst[2] = IP4->Dst.IP[2];	
		FlowPkt->IPDst[3] = IP4->Dst.IP[3];	

		FlowPkt->IPProto 	= IP4->Proto;
		FlowPkt->IPDSCP		= (IP4->Service >> 2);

		// drop the packet if its fragmented, as protocol header info
		// likely to be bogus
		u16 Frag = swap16(IP4->Frag); 
		if ((Frag & 0x1fff) != 0)
		{
			// count ip fragmentation 
			FlowPkt->IP4FragCnt++;

			// wireshark considers fragmented ip protocols to be
			// "data" packets without any protocol
			FlowPkt->IPProto	= 0; 
		}
		else
		{
			// IPv4 protocol decoders 
			u32 IPOffset = (IP4->Version & 0x0f)*4; 
			switch (IP4->Proto)
			{
			case IPv4_PROTO_TCP:
			{
				TCPHeader_t* TCP = (TCPHeader_t*)(Payload + IPOffset);

				// ensure TCP data is valid and not hashing 
				// random data in memeory
				if (((u8*)TCP - (u8*)Ether) + sizeof(TCPHeader_t) < PktHeader->LengthCapture)
				{
					FlowPkt->PortSrc	= swap16(TCP->PortSrc);
					FlowPkt->PortDst	= swap16(TCP->PortDst);

					// make a copy of the tcp header 
					FlowPkt->TCPHeader = TCP[0];

					// payload length
					u32 TCPOffset = ((TCP->Flags&0xf0)>>4)*4;
					FlowPkt->TCPLength =  swap16(IP4->Len) - IPOffset - TCPOffset;

					// check for options
					if (TCPOffset > 20)
					{
						u32 Timeout = 0;
						bool IsDone = false;
						u8* Options = (u8*)(TCP + 1);	
						while ( (Options - (u8*)TCP) < TCPOffset) 
						{
							if (IsDone) break;

							u32 Cmd = Options[0];
							u32 Len = Options[1];
							//printf("%i %i\n", Cmd, Len);
							switch (Cmd)
							{
							// end of list 
							case 0x0:
								IsDone = true;
								break;

							// NOP 
							case 0x1: 
								Len = 1;
								break;

							// MSS
							case 0x2: 
								break;

							// Window Scale
							case 0x3:
								//printf("Window Scale: %i\n", Options[2]);
								//FlowPkt->TCPWindowScale = Options[2];
								TCPWindowScale = Options[2];
								break;

							// SACK Enabled 
							case 0x4:
								{
									// SACK is present 
									FlowPkt->TCPIsSACK = TCP_SACK_ENABLE;
								}
								break;

							// SACK Payload
							case 0x5:
								{
									// ensure options length is valid (2 x 32 bit words)
									if (Len > 1)
									{
										u32  *D32 = (u32*)(Options + 2);
										// get 1st blocks byte delta
										// ignore any subsiquent left/right blocks
										// as only want to know if there was a gap, not how many 
										s32 Delta = swap32(D32[1]) - swap32(D32[0]);

										// if there is gaps 
										if (Delta > 1)
										{
											// flag all packets with SACK
											FlowPkt->TCPIsSACK |= TCP_SACK_OPTION;
										}
									}
								}
								break;

							// TSOpt
							case 0x8: 
								//printf("TCP Option TS\n");
								break;

							default:
								//printf("option: %i : %i\n", Cmd, Len); 
								break;
							}
							Options += Len;

							// invalid tcp option, length should always be > 0
							// exit processing loop 
							if ((!IsDone) && (Len == 0))
							{
								//printf("option: %i\n", Cmd);
								break;
							}
							assert(Timeout++ < 1e6);
						}
					}
				}
			}
			break;

			case IPv4_PROTO_UDP:
			{
				UDPHeader_t* UDP = (UDPHeader_t*)(Payload + IPOffset);

				FlowPkt->PortSrc	= swap16(UDP->PortSrc);
				FlowPkt->PortDst	= swap16(UDP->PortDst);
			}
			break;

			case IPv4_PROTO_ICMP:
			{
				ICMPHeader_t* ICMP = (ICMPHeader_t*)(Payload + IPOffset);

				switch (ICMP->Type)
				{
				//case ICMP_CODE_ECHO_REQ: 		FlowPkt->ICMPEchoReq 		= 1; break;
				//case ICMP_CODE_ECHO_REPLY: 		FlowPkt->ICMPEchoRes 		= 1; break;

				// deliberate fall thru, so IP info can be overwirtten 
				case ICMP_CODE_TIME_EXCEED: 			
				case ICMP_CODE_DEST_UNREACH:
				{
					// set in flow hash
					FlowPkt->ICMPType = ICMP->Type;

					// bit more detail
					if (ICMP->Type == ICMP_CODE_TIME_EXCEED) FlowPkt->ICMPTimeout 		= 1;
					else
					{
						FlowPkt->ICMPUnreach		= 1;
						/*
						switch (ICMP->Code)
						{
						case ICMP_UNREACH_NETWORK: 			FlowPkt->ICMPUnreachNet 			= 1; break;
						case ICMP_UNREACH_HOST: 			FlowPkt->ICMPUnreachHost 			= 1; break;
						case ICMP_UNREACH_PROTO: 			FlowPkt->ICMPUnreachProto 			= 1; break;
						case ICMP_UNREACH_PORT: 			FlowPkt->ICMPUnreachPort 			= 1; break;
						case ICMP_UNREACH_PROHIBIT_NET: 	FlowPkt->ICMPUnreachProhibitNet 	= 1; break;
						case ICMP_UNREACH_PROHIBIT_HOST: 	FlowPkt->ICMPUnreachProhibitHost 	= 1; break;
						case ICMP_UNREACH_PROHIBIT: 		FlowPkt->ICMPUnreachProhibit 		= 1; break;
						default:							FlowPkt->ICMPOther					= 1; break; 
						}
						*/
					}

					// overwrite the packets IP info from the ICMP unreachable header + time exeeded info 
					if (g_ICMPOverwrite)
					{
						// flag the flow info has been updated by the ICMP packet
						FlowPkt->ICMPOverwrite	= 1;

						// keep copy of ICMP src info
						FlowPkt->ICMPSrc		= IP4->Src;

						// skip
						u8* IPPayload	= (u8*)(ICMP + 1) + 4;

						// IP4 header
						IP4Header_t* UIP4 = (IP4Header_t*)IPPayload;
						FlowPkt->IPSrc[0] = UIP4->Src.IP[0];	
						FlowPkt->IPSrc[1] = UIP4->Src.IP[1];	
						FlowPkt->IPSrc[2] = UIP4->Src.IP[2];	
						FlowPkt->IPSrc[3] = UIP4->Src.IP[3];	

						FlowPkt->IPDst[0] = UIP4->Dst.IP[0];	
						FlowPkt->IPDst[1] = UIP4->Dst.IP[1];	
						FlowPkt->IPDst[2] = UIP4->Dst.IP[2];	
						FlowPkt->IPDst[3] = UIP4->Dst.IP[3];	

						FlowPkt->IPProto 	= UIP4->Proto;
						FlowPkt->IPDSCP		= 0; 

						// IPv4 protocol decoders 
						u32 IPOffset = (UIP4->Version & 0x0f)*4; 
						switch (UIP4->Proto)
						{
						case IPv4_PROTO_TCP:
						{
							TCPHeader_t* TCP = (TCPHeader_t*)(IPPayload + IPOffset);

							// ensure TCP data is valid and not hashing 
							// random data in memeory
							if (((u8*)TCP - (u8*)Ether) + sizeof(TCPHeader_t) < PktHeader->LengthCapture)
							{
								FlowPkt->PortSrc	= swap16(TCP->PortSrc);
								FlowPkt->PortDst	= swap16(TCP->PortDst);
							}
						}
						break;

						case IPv4_PROTO_UDP:
						{
							UDPHeader_t* UDP = (UDPHeader_t*)(IPPayload + IPOffset);

							FlowPkt->PortSrc	= swap16(UDP->PortSrc);
							FlowPkt->PortDst	= swap16(UDP->PortDst);
						}
						break;

						default:
							break;
						}
					}
				}
				break;

				//default:						FlowPkt->ICMPOther			= 1; break;
				}
			}
			break;
			}
		}
	}

	// generate SHA1
	// nice way to grab all packets for a single flow, search for the sha1 hash	
	// NOTE: FlowPktRecord_t setup so the first 64B contains only the flow info
	//       with packet and housekeeping info stored after. sha1_compress
	//       runs on the first 64B only 
	u64 TSC0 = rdtsc();

	u32 SHA1State[5] = { 0, 0, 0, 0, 0 };
	sha1_compress(SHA1State, (u8*)FlowPkt);

	FlowPkt->SHA1Half[0] = SHA1State[0];
	FlowPkt->SHA1Half[1] = SHA1State[1];
	FlowPkt->SHA1Half[2] = SHA1State[2];
	FlowPkt->SHA1Half[3] = SHA1State[3];
	FlowPkt->SHA1Half[4] = SHA1State[4];

	u64 TSC1 = rdtsc();
	s_DecodeThreadTSCHash[CPUID] += TSC1 - TSC0;

	if (FlowPkt->EtherProto == ETHER_PROTO_IPV4)
	{
		// Handle TCP event steam
		TCPFullDup_t TCPFullDup = { 0 };

		// Convert FlowPkt to determinstic TCPFullDup_t so we can create
		// full-duplex hash
		FlowPktToTCPFullDup(FlowPkt, &TCPFullDup);

		u64 TSC0 = rdtsc();

		u32 SHA1State[5] = { 0, 0, 0, 0, 0 };
		sha1_compress(SHA1State, (u8*)&TCPFullDup);
		FlowPkt->SHA1Full[0] = SHA1State[0];
		FlowPkt->SHA1Full[1] = SHA1State[1];
		FlowPkt->SHA1Full[2] = SHA1State[2];
		FlowPkt->SHA1Full[3] = SHA1State[3];
		FlowPkt->SHA1Full[4] = SHA1State[4];

		u64 TSC1 = rdtsc();
		s_DecodeThreadTSCHash[CPUID] += TSC1 - TSC0;

		u8 Buffer[8192];
		IP4Header_t* IP4 = (IP4Header_t*)Payload;
		FlowPkt->TCPEventCount = TCPEventDump(Buffer, s_TCP_Output, SnapshotTS, IP4, FlowPkt, TCPWindowScale);
		if (g_Output_TCP_STDOUT)
		{
			printf("%s", Buffer);
		}
	}

	// update the flow records
	if (g_IsJSONFlow)
	{
		// insert to flow table
		// NOTE: each CPU has its own FlowIndex no need to lock it 
		FlowInsert(CPUID, FlowIndex, FlowPkt, SHA1State, PktHeader->LengthWire, PktHeader->TS);
	}
	else if (g_IsJSONPacket)
	{
		// because TCPSACKCnt is set in FlowInsert update it
		// here so in packet mode the SACKCnt value is correct
		if (FlowPkt->TCPIsSACK &  TCP_SACK_OPTION)
		{
			FlowPkt->TCPSACKCnt++;
		}

		u8 Buffer[8192];
		FlowDump(Buffer, PktHeader->TS, FlowPkt, 0, 0);

		printf("%s", Buffer);
		//fflush(stdout);
	}
}

//---------------------------------------------------------------------------------------------
// queue a packet for processing 
static FlowIndex_t* s_FlowIndexQueue = NULL;
void Flow_PacketQueue(PacketBuffer_t* Pkt, bool IsFlush)
{
	// multi-core version
	if (!g_IsFlowNULL)
	{
		// wait for space int he queue 
		fProfile_Start(9, "DecodeQueueStall");

		u32 Timeout = 0; 
		while ((s_DecodeQueuePut  - s_DecodeQueueGet) >= (s_DecodeQueueMax - s_DecodeCPUActive - 4))
		{
			// update SHM Ring HB 
			g_BusyWaitFn();

			//ndelay(250);
			usleep(0);
//			assert(Timeout++ < 1e9);
		}
		fProfile_Stop(9);

		// add to processing queueDecodeQueueFlowAlloch
		s_DecodeQueue[s_DecodeQueuePut & s_DecodeQueueMsk] 	= Pkt;

		// allocate a new flow
		if (s_FlowIndexQueue == NULL)
		{
			fProfile_Start(10, "FlowIndexAlloc");

			s_FlowIndexQueue = FlowIndexAlloc();

			fProfile_Stop(10);
		}

		// set the flow index
		Pkt->IsFlowIndexDump	 = false;
		Pkt->FlowIndex			 = s_FlowIndexQueue; 

		Pkt->ID					= s_DecodeQueuePut;

		// set the total number of pktblocks for this index
		// so merge thread can block until all pktblocks have finished
		// processing
		Pkt->FlowIndex->PktBlockMax	+= 1;

		// purge the flow records every 100msec
		// as this is the singled threaded serialized
		// entry point, can flag it here instead of
		// in the worker threads
		if (s_FlowSampleTSLast  == 0)
		{
			s_FlowSampleTSLast  = (u64)(Pkt->TSLast / g_FlowSampleRate) * g_FlowSampleRate;

			if (g_Verbose)
			{
				fprintf(stderr, "first sample: %lli : %lli\n", Pkt->TSLast, s_FlowSampleTSLast);
			}
		}

		// time to dump the index
		s64 dTS = Pkt->TSLast - s_FlowSampleTSLast;
		//if (g_Verbose)
		//{
		//	fprintf(stderr, "next %lli %lli %lli\n", dTS, Pkt->TSLast, s_FlowSampleTSLast);
		//}

		if (dTS > g_FlowSampleRate)
		{
			Pkt->IsFlowIndexDump	= true;
			Pkt->TSSnapshot	 		= s_FlowSampleTSLast;

			// add next snapshot time 
			while ((Pkt->TSLast - s_FlowSampleTSLast) > g_FlowSampleRate)
			{
				s_FlowSampleTSLast 		+= g_FlowSampleRate; 
			}

			// force new allocation on next Queue 
			s_FlowIndexQueue = NULL;
		}

		// force flush, for final output
		if (IsFlush)
		{
			Pkt->IsFlowIndexDump	= true;
			Pkt->IsFlowIndexFlush	= (g_FlowIndexRollWrite != NULL);
			Pkt->TSSnapshot	 		= s_FlowSampleTSLast;

			// force new allocation on next Queue 
			s_FlowIndexQueue 		= NULL;
		}

		s_DecodeQueuePut++;
		s_PacketQueueCnt++;
	}
	else
	{
		// benchmarking mode just release the buffer
		Flow_PacketFree(Pkt);
	}
}

//---------------------------------------------------------------------------------------------

void* Flow_Worker(void* User)
{
	u32 CPUID = __sync_fetch_and_add(&s_DecodeCPUActive, 1);

	FlowIndex_t* FlowIndexLast = NULL;

	u8	SortListDepth = ((g_FlowTopNMac) ? g_FlowTopNMac + 1 : 1);
	u32	SortListCnt[SortListDepth];
	u32* SortList[SortListDepth];

	for (int i=0; i < SortListDepth; i++)
	{
		SortList[i] = malloc(sizeof(u64) * s_FlowMax * 3);
		assert(SortList[i] != NULL);
	}
	memset(&SortListCnt, 0, sizeof(SortListCnt));

	fprintf(stderr, "Start decoder thread: %i\n", CPUID);
	while (!s_Exit)
	{
		u64 TSC0 = rdtsc();

		u32 Get = s_DecodeQueueGet;
		if (Get == s_DecodeQueuePut)
		{
			// nothing to do
			//ndelay(100);
			usleep(0);
		}
		else
		{
			// fetch the to be processed pkt *before* atomic lock 
			PacketBuffer_t* PktBlock = (PacketBuffer_t*)s_DecodeQueue[Get & s_DecodeQueueMsk];
			assert(PktBlock != NULL);

			// get the entry atomically 
			if (__sync_bool_compare_and_swap(&s_DecodeQueueGet, Get, Get + 1))
			{

// back pressure testing
//u32 delay =  ((u64)rand() * 100000000ULL) / (u64)RAND_MAX; 
//ndelay(delay);

				u64 TSC2 = rdtsc();

				// ensure no sync problems
				assert(PktBlock->ID == Get);

				// root index
				FlowIndex_t* FlowIndexRoot = PktBlock->FlowIndex;

				// assigned index to add the packet to
				FlowIndex_t* FlowIndex = FlowIndexRoot + CPUID; 

				// find spare FlowIndex for sorted output
				FlowIndex_t* FlowSort = FlowIndexRoot + ((CPUID + 1) % s_DecodeCPUActive);

				// process all packets in this block 
				u32 Offset = 0;
				u64 TSLast = 0;
				for (int i=0; i < PktBlock->PktCnt; i++)
				{
					FMADPacket_t* PktHeader = (FMADPacket_t*)(PktBlock->Buffer + Offset);

					Offset += sizeof(PCAPPacket_t) + PktHeader->LengthCapture;

					assert(PktHeader->LengthWire    > 0); 
					assert(PktHeader->LengthCapture	> 0); 

					assert(PktHeader->LengthWire    < 16*1024);
					assert(PktHeader->LengthCapture < 16*1024);

					// process the packet
					DecodePacket(CPUID, s_Output, (u64) (PktBlock->TSFirst / g_FlowSampleRate) * g_FlowSampleRate, PktHeader, FlowIndex);

					// update size histo
					u32 SizeIndex = (PktHeader->LengthWire / s_PacketSizeHistoBin);
					if (SizeIndex >= s_PacketSizeHistoMax) SizeIndex = s_PacketSizeHistoMax - 1;
					s_PacketSizeHisto[CPUID][SizeIndex]++;
				}

				__sync_fetch_and_add(&s_PktCntTotal, PktBlock->PktCnt);

				// output the snapshot  
				if (PktBlock->IsFlowIndexDump)
				{
					// flow snapshot merging and output 
					if (g_IsJSONFlow)
					{
						// write to output
						u64 TSC0 = rdtsc();

						// wait for all workers to complete
						// ensures workers processing on Indexs 
						// that need to be aggregated into this one
						// have completed processing
						u32 Timeout = 0; 
						while (FlowIndexRoot->PktBlockCnt < FlowIndexRoot->PktBlockMax - 1)
						{
							usleep(0);
							assert(Timeout++ < 1e6);	
						}
						u64 TSC1 = rdtsc();

						// merge everything into this CPUs index 
						// merge flows
						FlowMerge(FlowIndex, FlowIndexRoot, s_FlowIndexSub);

						// merge int preloadded snapshot
						if (PktBlock->TSSnapshot == s_FlowPreloadTS)
						{
							FlowMergePreload(FlowIndex);
						}

						// if top talkers is enabled, reduce the flow list
						if (g_FlowTopNEnable)
						{
							for (int i=0; i < g_FlowTopNMac; i++)
							{
								if (g_FlowTopNMac)
								{
									SortListCnt[i] = FlowTopN(SortList[i], FlowIndex, g_FlowTopNMax, g_FlowTopNsMac[i], g_FlowTopNdMac[i]);
								}
								else
								{
									SortListCnt[i] = FlowTopN(SortList[i], FlowIndex, g_FlowTopNMax, NULL, NULL);
								}
							}
							// we need default TopN in all the cases
							SortListCnt[g_FlowTopNMac] = FlowTopN(SortList[g_FlowTopNMac], FlowIndex, g_FlowTopNMax, NULL, NULL);
						}
						// use a linear map / no sorting 
						else
						{
							SortListCnt[0] = FlowIndex->FlowCntSnapshot;
							for (int i=0; i < FlowIndex->FlowCntSnapshot; i++)
							{
								SortList[0][i] = i;
							}
						}

						u64 TSC2 = rdtsc();

						u64 StallTSC = 0;
						u64 TotalPkt = 0;

						u8* JSONBuffer 			= FlowIndexRoot->JSONBuffer;
						u32 JSONBufferOffset 	= 0;
						u32 JSONLineCnt			= 0;

						// count total flows in this snapshot
						u32 FlowTotal			= 0; 
						for (int j=0; j < SortListDepth; j++)
						{
							for (int i=0; i < SortListCnt[j]; i++)
							{
								FlowTotal++;
							}
						}

						// write to downstream 
						if (!PktBlock->IsFlowIndexFlush)
						{
							// dump all flows
							u32 FlowDepthTotal		 = 0;
							u32 FlowCnt = 0;
							for (int j=0; j < SortListDepth; j++)
							{
								for (int i=0; i < SortListCnt[j]; i++)
								{
									u32 FIndex =  SortList[j][i];
									FlowRecord_t* Flow = &FlowIndex->FlowList[ FIndex ];	
									// Can't have more events than packets in the flow record
									assert(Flow->TotalPkt >= Flow->TCPEventCount);

									JSONBufferOffset += FlowDump(JSONBuffer + JSONBufferOffset, PktBlock->TSSnapshot, Flow, FlowCnt, FlowTotal);
									JSONLineCnt++;

									// flush to output 
									if (JSONBufferOffset > FlowIndexRoot->JSONBufferMax - kKB(16))
									{
										StallTSC += Output_BufferAdd(s_Output, JSONBuffer, JSONBufferOffset, JSONLineCnt);

										JSONBufferOffset 	= 0;
										JSONLineCnt 		= 0;
									}
									TotalPkt += Flow->TotalPkt;

									// update flow depth histogram
									u32 HIndex = Flow->TotalPkt / s_FlowDepthHistoBin;
									if (HIndex >= s_FlowDepthHistoMax) HIndex = s_FlowDepthHistoMax - 1;
									s_FlowDepthHisto	[CPUID][HIndex]++;
									s_FlowDepthHistoCnt	[CPUID]++;
									FlowDepthTotal++;
									FlowCnt++;
								}
							}


							// find median flow depth
							u32 FlowDepthSum = 0;
							for (int i=0; i < s_FlowDepthHistoMax; i++)
							{
								FlowDepthSum += s_FlowDepthHisto[CPUID][i];
								if (FlowDepthSum  >= FlowDepthTotal / 2)
								{
									s_FlowDepthMedian = i * s_FlowDepthHistoBin; 
									break;
								}
							}
						}
						// flush partial snapshot, so next spinup can load 
						else
						{

							FILE* F = fopen(g_FlowIndexRollWrite, "w+");
							assert(F != NULL);

							for (int j=0; j < SortListDepth; j++)
							{
								for (int i=0; i < SortListCnt[j]; i++)
								{
									u32 FIndex =  SortList[j][i];
									FlowRecord_t* Flow = &FlowIndex->FlowList[ FIndex ];	

									// set snapshot TS
									Flow->SnapshotTS = PktBlock->TSSnapshot;

									// write flow to disk 
									fwrite(Flow, 1, sizeof(FlowRecord_t), F);
								}
							}
							fclose(F);
						}

						u64 TSC3 = rdtsc();

						// flush remaining lines in the buffer 
						StallTSC += Output_BufferAdd(s_Output, JSONBuffer, JSONBufferOffset, JSONLineCnt);

						// add total number of flows output 
						s_FlowCntTotal += FlowIndex->FlowCntSnapshot;

						// save total merged flow count 
						s_FlowCntSnapshotLast = FlowIndex->FlowCntSnapshot;
						s_PktCntSnapshotLast  = TotalPkt; 

						u64 TSC4 = rdtsc();
						//assert(FlowIndexRoot->IsUse == true);


						u64 TSC5 						= rdtsc();
						s_DecodeThreadTSCOutput	[CPUID] += TSC4 - TSC0;
						s_DecodeThreadTSCOStall	[CPUID] += StallTSC;
						s_DecodeThreadTSCMerge 	[CPUID] += TSC2 - TSC1; 
						s_DecodeThreadTSCWrite 	[CPUID] += TSC3 - TSC2; 
						s_DecodeThreadTSCOut	[CPUID] += TSC4 - TSC3;
						s_DecodeThreadTSCReset	[CPUID] += TSC5 - TSC4;
						s_DecodeThreadTSCWorker	[CPUID] += TSC1 - TSC0;
					}

					// release the root index + cpu subs 
					// NOTE: in packet mode need to release this also 
					FlowIndexFree(FlowIndexRoot);
				}
				else
				{
					// update pktblock count for the root index
					// NOTE: as FlowIndexRoot is freeed on flush above, only increment the coutner
					//       when there is no flush
					__sync_fetch_and_add(&FlowIndexRoot->PktBlockCnt, 1);
				}

				// release buffer
				Flow_PacketFree(PktBlock);

				// update counter
				__sync_fetch_and_add(&s_PacketDecodeCnt, 1);

				// cpu usage stats
				u64 TSC3 = rdtsc();
				s_DecodeThreadTSCDecode[CPUID] += TSC3 - TSC2;
			}
		}

		u64 TSC1 = rdtsc();
		s_DecodeThreadTSCTop[CPUID] += TSC1 - TSC0;
	}

	fprintf(stderr, "flow exit %i\n", CPUID);
}

//---------------------------------------------------------------------------------------------
// packet buffer management 
PacketBuffer_t* Flow_PacketAlloc(void)
{
	// stall waiting for free buffer
	u32 Timeout = 0;
	while (true)
	{
		if (s_PacketBuffer != NULL) break;

		// update SHM Ring HB 
		g_BusyWaitFn();

		usleep(0);
		//ndelay(100);
		assert(Timeout++ < 1e6);
	}

	// acquire lock
	PacketBuffer_t* B = NULL; 
	sync_lock(&s_PacketBufferLock, 50);
	{
		B = (PacketBuffer_t*)s_PacketBuffer;
		assert(B != NULL);

		s_PacketBuffer = B->FreeNext;

		// release lock
		assert(s_PacketBufferLock == 1); 
	}
	sync_unlock(&s_PacketBufferLock);

	// double check its a valid free pkt
	assert(B->IsUsed == false);
	B->IsUsed = true;

	// reset stats
	B->PktCnt			= 0;
	B->ByteWire			= 0;
	B->ByteCapture		= 0;
	B->TSFirst			= 0;
	B->TSLast			= 0;
	B->IsFlowIndexDump	= false;
	B->IsFlowIndexFlush	= false;

	return B;
}

void Flow_PacketFree(PacketBuffer_t* B)
{
	// acquire lock
	sync_lock(&s_PacketBufferLock, 100); 
	{
		// push at head
		B->FreeNext 	= (PacketBuffer_t*)s_PacketBuffer;
		s_PacketBuffer 	= B;

		B->IsUsed = false;

		// release lock
		assert(s_PacketBufferLock == 1); 
	}
	sync_unlock(&s_PacketBufferLock);
}

//---------------------------------------------------------------------------------------------
// allocate memory and house keeping
void Flow_Open(struct Output_t* Out, struct Output_t* OutTCP, u32 CPUMapCnt, s32* CPUMap, u32 FlowIndexDepth, u64 FlowMax)
{
	assert(Out != NULL);

	s_Output 	= Out;
	s_TCP_Output 	= OutTCP;
	s_FlowMax	= FlowMax;

	// allocate packet buffers
	for (int i=0; i < s_PacketBufferMax; i++)
	{
		PacketBuffer_t* B = &s_PacketBufferList[i];
		memset(B, 0, sizeof(PacketBuffer_t));

		B->BufferMax 	= 256*1024 + 1024;
		B->Buffer 		= memalign(4096, B->BufferMax);
		memset(B->Buffer, 0, B->BufferMax);	

		Flow_PacketFree(B);
	}

	// create worker threads
	u32 CPUCnt = 0;

	for (int i=0; i < CPUMapCnt; i++)
	{
		pthread_create(&s_DecodeThread[i], NULL, Flow_Worker, (void*)NULL); 
		CPUCnt++;
	}

	for (int i=0; i < CPUCnt; i++)
	{
		if (CPUMap[i] <= 0) continue; 
		
		cpu_set_t Thread0CPU;
		CPU_ZERO(&Thread0CPU);
		CPU_SET (CPUMap[i], &Thread0CPU);
		pthread_setaffinity_np(s_DecodeThread[i], sizeof(cpu_set_t), &Thread0CPU);
	}

	s_FlowIndexMax = FlowIndexDepth * CPUCnt; 
	s_FlowIndexSub = CPUCnt; 

	u64 TotalMem = 0;

	// allocate flow indexes
	for (int i=0; i < s_FlowIndexMax; i++)
	{
		FlowIndex_t* FlowIndex = &s_FlowIndex[i];

		// max out at 250K flows
		FlowIndex->FlowMax	= FlowMax;

		// allocate and clear flow index
		FlowIndex->FlowHash = (u32*)memalign(4096, sizeof(u32) * (2 << 20) );
		assert(FlowIndex->FlowHash != NULL);

		FlowIndex->FlowHashFrameID = (u16*)memalign(4096, sizeof(u16) * (2 << 20) );
		assert(FlowIndex->FlowHashFrameID != NULL);

		FlowIndex->FrameID = 1;

		// allocate statically allocated flow list
		FlowIndex->FlowList = (FlowRecord_t *)memalign (4096, sizeof(FlowRecord_t) * FlowIndex->FlowMax );
		assert(FlowIndex->FlowList != NULL);

		TotalMem += sizeof(FlowRecord_t *) * (2 << 20);
		TotalMem += sizeof(FlowRecord_t) * FlowIndex->FlowMax;
		//printf("mem: %.f MB\n", TotalMem / 1e6);
	}

	// allocate JSON output buffer on the index root 
	for (int i=0; i < s_FlowIndexMax; i += s_FlowIndexSub)
	{
		FlowIndex_t* FlowIndex = &s_FlowIndex[i];

		FlowIndex->JSONBufferMax	= kMB(1);
		FlowIndex->JSONBuffer		= malloc(FlowIndex->JSONBufferMax);
		assert(FlowIndex->JSONBuffer != NULL);
	}

	// push to free list
	for (int i=0; i < s_FlowIndexMax; i += s_FlowIndexSub)
	{
		FlowIndex_t* FlowIndex = &s_FlowIndex[i];
		for (int j=0; j < s_FlowIndexSub; j++)
		{
			(FlowIndex+j)->IsUse = true;
		}
		FlowIndexFree(FlowIndex);
	}

	// reset histogram
	memset(s_PacketSizeHisto, 0, sizeof(s_PacketSizeHisto));

	// ensure first 64B of flow record is correctly aligned
	fprintf(stderr, "Flow Record %i\n", offsetof(FlowRecord_t, TCPACKCnt));
	assert(offsetof(FlowRecord_t, TCPACKCnt) == 64);

	// attempt to load any previous flow data
	if (g_FlowIndexRollRead)
	{
		FILE* F = fopen(g_FlowIndexRollRead, "r");
		if (F)
		{
			struct stat s;
			stat(g_FlowIndexRollRead, &s);

			u64 FlowSize 		= s.st_size;	
			s_FlowPreloadCnt	= FlowSize / sizeof(FlowRecord_t);
			s_FlowPreload 		= malloc( FlowSize );
			for (int i=0; i < s_FlowPreloadCnt; i++)
			{
				FlowRecord_t* Flow = s_FlowPreload + i;	
				fread(Flow,  1, sizeof(FlowRecord_t), F);

				// set the snapshot this preload belongs to 
				//printf("%lli : %lli\n",  Flow->SnapshotTS, Flow->FirstTS); 
				s_FlowPreloadTS = Flow->SnapshotTS; 	
			}
			printf("Preload: %i %lli\n", s_FlowPreloadCnt, s_FlowPreloadTS);
		}
	}
}

//---------------------------------------------------------------------------------------------
// shutdown / flush
void Flow_Close(struct Output_t* Out, u64 LastTS)
{
	fprintf(stderr, "flow close %x\n", s_DecodeQueuePut);

	// push a flush packet
	// this ensures the last flow data gets flushed to the output queue
	// in a fully pipelined manner 
	PacketBuffer_t*	PktBlock 	= Flow_PacketAlloc();
	PktBlock->PktCnt			= 0;
	Flow_PacketQueue(PktBlock, true);

	// wait for all queues to drain
	u32 Timeout = 0;
	while (s_DecodeQueuePut != s_DecodeQueueGet)
	{
		fprintf(stderr, "flow close wait %x %x\n", s_DecodeQueuePut, s_DecodeQueueGet);
		usleep(100e3);
		assert(Timeout++ < 1e6);
	}
	fprintf(stderr, "close finish %x %x\n", s_DecodeQueuePut, s_DecodeQueueGet);

	s_Exit = true;

	fprintf(stderr, "QueueCnt : %lli\n", s_PacketQueueCnt);	
	fprintf(stderr, "DecodeCnt: %lli\n", s_PacketDecodeCnt);	

	fprintf(stderr, "Flow Join\n");
	for (int i=0; i < s_DecodeCPUActive; i++)
	{
		fprintf(stderr, "  Worker %i\n", i);
		pthread_join(s_DecodeThread[i], NULL);
	}
	fprintf(stderr, "Flow Close\n");
}

//---------------------------------------------------------------------------------------------

void Flow_Stats(	bool IsReset, 
					u64* pFlowCntSnapShot, 
					u64* pPktCntSnapShot, 
					u64* pFlowCntTotal, 
					float* pFlowDepthMedian,

					float * pCPUDecode,
					float * pCPUHash,
					float * pCPUOutput,
					float * pCPUOStall,
					float * pCPUMerge,
					float * pCPUWrite,
					float * pCPUReset,
					float * pCPUWorker
){
	if (pFlowCntSnapShot)	pFlowCntSnapShot[0] = s_FlowCntSnapshotLast;
	if (pPktCntSnapShot)	pPktCntSnapShot[0]	= s_PktCntSnapshotLast;

	if (pFlowCntTotal)		pFlowCntTotal[0]	= s_FlowCntTotal;
	if (pFlowDepthMedian)	pFlowDepthMedian[0]	= s_FlowDepthMedian;

	u64 TotalTSC 	= 0;
	u64 DecodeTSC 	= 0;
	u64 HashTSC  	= 0;
	u64 OutputTSC	= 0;
	u64 OStallTSC	= 0;
	u64 MergeTSC	= 0;
	u64 WriteTSC	= 0;
	u64 OutTSC		= 0;
	u64 ResetTSC	= 0;
	u64 WorkerTSC	= 0;

	for (int i=0; i < s_DecodeCPUActive; i++)
	{
		TotalTSC 	+= s_DecodeThreadTSCTop		[i];
		DecodeTSC 	+= s_DecodeThreadTSCDecode	[i];
		HashTSC 	+= s_DecodeThreadTSCHash	[i];
		OutputTSC 	+= s_DecodeThreadTSCOutput	[i];
		OStallTSC 	+= s_DecodeThreadTSCOStall	[i];
		MergeTSC 	+= s_DecodeThreadTSCMerge	[i];
		WriteTSC 	+= s_DecodeThreadTSCWrite	[i];
		OutTSC	 	+= s_DecodeThreadTSCOut		[i];
		ResetTSC 	+= s_DecodeThreadTSCReset	[i];
		WorkerTSC 	+= s_DecodeThreadTSCWorker	[i];
	}

	if (IsReset)
	{
		for (int i=0; i < s_DecodeCPUActive; i++)
		{
			s_DecodeThreadTSCTop[i]		= 0;
			s_DecodeThreadTSCDecode[i]	= 0;
			s_DecodeThreadTSCHash[i]	= 0;
			s_DecodeThreadTSCOutput[i]	= 0;
			s_DecodeThreadTSCOStall[i]	= 0;
			s_DecodeThreadTSCMerge[i]	= 0;
			s_DecodeThreadTSCWrite[i]	= 0;
			s_DecodeThreadTSCOut[i]		= 0;
			s_DecodeThreadTSCReset[i]	= 0;
			s_DecodeThreadTSCWorker[i]	= 0;
		}
	}

	if (pCPUDecode) pCPUDecode[0] 	= DecodeTSC * inverse(TotalTSC);
	if (pCPUHash) 	pCPUHash[0] 	= HashTSC 	* inverse(TotalTSC);
	if (pCPUOutput) pCPUOutput[0] 	= OutputTSC * inverse(TotalTSC);
	if (pCPUOStall) pCPUOStall[0] 	= OStallTSC	* inverse(TotalTSC);
	if (pCPUMerge)  pCPUMerge[0] 	= MergeTSC	* inverse(TotalTSC);
	if (pCPUWrite)  pCPUWrite[0] 	= WriteTSC	* inverse(TotalTSC);
	if (pCPUReset)  pCPUReset[0] 	= ResetTSC	* inverse(TotalTSC);
	if (pCPUWorker)  pCPUWorker[0] 	= WorkerTSC	* inverse(TotalTSC);
}

//---------------------------------------------------------------------------------------------
// dump + reset the packet size histogram
void Flow_PktSizeHisto(void)
{
	fprintf(stderr, "Packet Size Histogram:\n");	

	// merge into single histogram
	u32 TotalSamples = 0;
	u32 SizeHisto[1024];
	memset(SizeHisto, 0, sizeof(SizeHisto));
	for (int c=0; c < s_DecodeCPUActive; c++)
	{
		for (int i=0; i < s_PacketSizeHistoMax; i++)
		{
			u32 Cnt = s_PacketSizeHisto[c][i];
			SizeHisto[i] += Cnt; 
			TotalSamples += Cnt; 
		}
	}
	memset(s_PacketSizeHisto, 0, sizeof(s_PacketSizeHisto));

	// find max per bin
	u32 MaxCnt = 0;
	for (int i=0; i < s_PacketSizeHistoMax; i++)
	{
		MaxCnt = (MaxCnt < SizeHisto[i]) ? SizeHisto[i] : MaxCnt;
	}
	float iMaxCnt = inverse(MaxCnt);	
	float iTotal = inverse(TotalSamples);

	// print status
	float CDF = 0;
	for (int i=0; i < s_PacketSizeHistoMax; i++)
	{
		u32 Size = i * s_PacketSizeHistoBin;
		if (SizeHisto[i] == 0) continue;

		CDF  += SizeHisto[i] * iTotal;

		fprintf(stderr, "%5i : %.3f : %10i (%.3f) : %.3f : ", Size, CDF, SizeHisto[i], SizeHisto[i] * iTotal);
		u32 Cnt = (SizeHisto[i] * 80 ) * iMaxCnt;
		for (int j=0; j < Cnt; j++) fprintf(stderr, "*");

		fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");

	// merge flow histo
	u32 FlowDepthHisto[128];
	u32 FlowDepthHistoCnt = 0;
	memset(FlowDepthHisto, 0, sizeof(FlowDepthHisto));

	fprintf(stderr, "Flow Depth Histogram\n");
	for (int c=0; c < s_DecodeCPUActive; c++)
	{
		FlowDepthHistoCnt += s_FlowDepthHistoCnt[c];
		for (int i=0; i < s_FlowDepthHistoMax; i++)
		{
			FlowDepthHisto[i] += s_FlowDepthHisto[c][i];
			s_FlowDepthHisto[c][i] = 0;
		}
		s_FlowDepthHistoCnt[c] = 0;
	}

	float Total = 0;
	float ooCnt = inverse(FlowDepthHistoCnt);
	for (int i=0; i < s_FlowDepthHistoMax; i++)
	{
		if (FlowDepthHisto[i] > 0)
		{
			fprintf(stderr, "%4i : (%.3f) %.3f : ", i * s_FlowDepthHistoBin, Total, FlowDepthHisto[i] * ooCnt); 

		 	u32 Cnt = (FlowDepthHisto[i] * 80 ) * ooCnt;
			for (int j=0; j < Cnt; j++) fprintf(stderr, "*");
			fprintf(stderr, "\n");
		}
		Total += FlowDepthHisto[i] * ooCnt; 
	}
}

/* vim: set ts=4 sts=4 */
