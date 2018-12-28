#ifndef _PCAP2JSON_FLOW_H__
#define _PCAP2JSON_FLOW_H__

struct Output_t;
struct FlowIndex_t;

typedef struct FMADPacket_t
{
	u64             TS;                     // 64bit nanosecond epoch

	u32             LengthCapture   : 16;   // length captured
	u32             LengthWire      : 16;   // Length on the wire

	u32             PortNo          :  8;   // Port number
	u32             Flag            :  8;   // flags
	u32             pad0            : 16;

} __attribute__((packed)) FMADPacket_t;

// header per packet
typedef struct FMADHeader_t
{
	u16				PktCnt;					// number of packets
	u16				pad0;

	u32				BytesWire;				// total wire bytes  
	u32				BytesCapture;			// total capture bytes 
	u32				Length;					// length of this block in bytes

	u64				TSStart;				// TS of first packet
	u64				TSEnd;					// TS of last packet 

} __attribute__((packed)) FMADHeader_t;


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
	struct FlowIndex_t*		FlowIndex;			// which flow index to use

	struct PacketBuffer_t*	FreeNext;			// next in free list

	volatile bool			IsUsed;				// sanity checking confirm single ownership
	u32						ID;					// flow control sanity check

} PacketBuffer_t;


void 			Flow_Open				(struct Output_t* Out, s32* CPUMap);
void 			Flow_Close				(struct Output_t* Out, u64 LastTS);
void 			Flow_Stats				(bool IsReset,
										 u32* pFlowCntSnapShot,
										 u64* pFlowCntTotal,
										 float* pCPUUse, 
										 float* pCPUHash,
										 float* pCPUOutput
										);

void 			Flow_PacketQueue		(PacketBuffer_t* Pkt);

PacketBuffer_t* Flow_PacketAlloc		(void);
void 			Flow_PacketFree			(PacketBuffer_t* B);

#endif
