#ifndef _PCAP2JSON_FLOW_H__
#define _PCAP2JSON_FLOW_H__

struct Output_t;
struct FlowIndex_t;

typedef struct PacketBuffer_t
{
	u32						BufferMax;			// max size
	u8*						Buffer;				// memory buffer

	u64						TS;					// timestamp of this packet
	bool					IsFlowIndexDump;	// time to dump the sample
	struct FlowIndex_t*		FlowIndex;			// which flow index to use

	struct PacketBuffer_t*	FreeNext;			// next in free list

	volatile bool			IsUsed;	

} PacketBuffer_t;


void 			Flow_Open				(struct Output_t* Out);
void 			Flow_Close				(struct Output_t* Out, u64 LastTS);
void 			Flow_Stats				(bool IsReset, u32* pFlowCntSnapShot, u64* pFlowCntTotal, float * pCPUUse);

void 			Flow_PacketQueue		(PacketBuffer_t* Pkt);

PacketBuffer_t* Flow_PacketAlloc		(void);
void 			Flow_PacketFree			(PacketBuffer_t* B);

#endif
