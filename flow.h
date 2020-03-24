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


typedef struct FlowRecord_t 
{
	u16						EtherProto;			// ethernet protocol
	u8						EtherSrc[6];		// ethernet src mac
	u8						EtherDst[6];		// ethernet dst mac

	u16						VLAN[4];			// vlan tags


	u16						MPLS1;				// MPLS 1 tags
	u16						MPLStc1;			// MPLS 1 traffic class 

	u16						MPLS2;				// MPLS 1 tags
	u16						MPLStc2;			// MPLS 1 traffic class 

	u16						MPLS3;				// MPLS 2 tags
	u16						MPLStc3;			// MPLS 2 traffic class 

	u8						IPSrc[4];			// source IP
	u8						IPDst[4];			// source IP

	u8						IPProto;			// IP protocol
	u8						IPDSCP;				// IP DSCP flag

	u16						PortSrc;			// tcp/udp port source
	u16						PortDst;			// tcp/udp port source

	u8						pad[16];			// SHA1 calcuated on the first 64B

	//----------------------------------------------------------------------------
	// anything above the line is used for unique per flow hash


	u16						TCPACKCnt;			// TCP ACK count within the time period	
	u16						TCPFINCnt;			// TCP FIN count within the time period	
	u16						TCPSYNCnt;			// TCP SYN count within the time period	
	u16						TCPPSHCnt;			// TCP PSH count within the time period	
	u16						TCPRSTCnt;			// TCP RST count within the time period	
	u16						TCPWindowMin;		// TCP Window Minimum 
	u16						TCPWindowMax;		// TCP Window Maximum 

	u16						TCPACKDupCnt;		// number of TCP duplicate acks seen
	u16						TCPSACKCnt;			// number of TCP SACK acknowledgements 

	u32						TCPSeqNo;			// last TCP Seq no seen
	u32						TCPAckNo;			// last TCP Ack no seen
	u32						TCPAckNoCnt;		// number of acks for this seq no 
	u16						TCPLength;			// tcp payload length
	u8						TCPIsSACK;			// if this packet is SACK
	u32						TCPWindowScale;		// tcp window scaling factor

	u16						MPLS0;				// MPLS 0 tags
	u16						MPLStc0;			// MPLS 0 traffic class 
												// NOTE: request the outer MPLS tag
												//       not be included in the hash calculation
												// 		 see https://github.com/fmadio/pcap2json/issues/15 

	//-------------------------------------------------------------------------------
	
	u32						SHA1[5];			// SHA of the flow

	u64						SnapshotTS;			// snapshot of the snapshot 
	u64						FirstTS;			// first TS seen
	u64						LastTS;				// last TS seen 

	u64						TotalPkt;			// total packets
	u64						TotalByte;			// total bytes
	u64						TotalFCS;			// total number of FCS errors

	TCPHeader_t				TCPHeader;			// copy of the TCP Header

	u8						StrProtoMAC[8];		// text description of MAC rptocol 
	u8						StrProtoFlow[8];	// text description of protocol 
	u8						StrProtoIP[8];		// text description of IP protocol 
	u8						StrDSCP[8];			// text description of DSCP 

	u8						SortDone;			// for top talkers, if this entry has been consumed

	struct PacketInfoBulk_t	*PktInfoB;
	struct FlowRecord_t*	Next;				// next flow record
	struct FlowRecord_t*	Prev;				// previous flow record

} __attribute__((packed)) FlowRecord_t;

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

void 			Flow_PacketQueue		(PacketBuffer_t* Pkt, bool IsFlush);

PacketBuffer_t* Flow_PacketAlloc		(void);
void 			Flow_PacketFree			(PacketBuffer_t* B);

#define MAX_TOPN_MAC 64

#define MAC_FMT			"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define MAC_PRINT(m)	(m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

#define MAC_PRNT_S(fr)	MAC_PRINT((fr)->EtherSrc)
#define MAC_PRNT_D(fr)	MAC_PRINT((fr)->EtherDst)

#define MAC_CMP(a, b)	((a)[0] == (b)[0] && (a)[1] == (b)[1] && (a)[2] == (b)[2] && (a)[3] == (b)[3] && (a)[4] == (b)[4] && (a)[5] == (b)[5])

#endif
