#ifndef _PCAP2JSON_FLOW_H__
#define _PCAP2JSON_FLOW_H__

struct Output_t;
struct FlowIndex_t;

typedef struct PacketBuffer_t
{
	u32						PktCnt;				// number of packets in this buffer
	u32						ByteWire;			// total wire bytes 
	u32						ByteCapture;		// total captured bytes 

	u64						TSFirst;			// first Pkt TS
	u64						TSLast;				// last Pkt TS

	u32						BufferMax;			// max size
	u8*						Buffer;				// memory buffer
	u32						BufferLength;		// length of valid data in buffer

	bool					IsFlowIndexDump;	// time to dump the sample
	u64						TSSnapshot;			// TS for the snapshot to be output
	struct FlowIndex_t*		FlowIndex;			// which flow index to use

	struct PacketBuffer_t*	FreeNext;			// next in free list

	volatile bool			IsUsed;				// sanity checking confirm single ownership
	u32						ID;					// flow control sanity check

} PacketBuffer_t;

void 			Flow_Open				(struct Output_t* Out, u32 CPUMapCnt, s32* CPUMap, u32 FlowIndexDepth, u64 FlowMax, u8* FlowTemplate);
void 			Flow_Close				(struct Output_t* Out, u64 LastTS);
void 			Flow_Stats				(bool   IsReset,
										 u64*   pFlowCntSnapShot,
										 u64*   pPktCntSnapShot,
										 u64*   pFlowCntTotal,
										 float* pFlowDepthMedian,
										 float* pCPUUse, 
										 float* pCPUHash,
										 float* pCPUOutput,
										 float* pCPUOStall,
										 float* pCPUMerge,
										 float* pCPUWrite,
										 float* pCPUReset,
										 float* pCPUWorker
										);
void 			Flow_PktSizeHisto		(void);

void 			Flow_PacketQueue		(PacketBuffer_t* Pkt);

PacketBuffer_t* Flow_PacketAlloc		(void);
void 			Flow_PacketFree			(PacketBuffer_t* B);

#define MAX_TOPN_MAC 64

#define MAC_FMT			"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define MAC_PRINT(m)	(m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

#define MAC_PRNT_S(fr)	MAC_PRINT((fr)->EtherSrc)
#define MAC_PRNT_D(fr)	MAC_PRINT((fr)->EtherDst)

#define MAC_CMP(a, b)	((a)[0] == (b)[0] && (a)[1] == (b)[1] && (a)[2] == (b)[2] && (a)[3] == (b)[3] && (a)[4] == (b)[4] && (a)[5] == (b)[5])

#endif
