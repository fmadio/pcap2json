#ifndef _PCAP2JSON_TCPEVENT_H__
#define _PCAP2JSON_TCPEVENT_H__

extern bool			g_Output_TCP_STDOUT;			// by default output TCP to stdout
extern u8*				g_Output_TCP_PipeName;			// name of TCP pipe to

typedef struct
{
	u64		SnapshotTS;			// timestamp of last byte
	u32		Event;					// 32-bit TCP event - with flag+OP
	u16		Length;				// number of bytes in this packet
	u32		HashFullDuplex[5];		// full-duplex hash

	u32		SeqNo;				// current tcp seq no
	u32		AckNo;				// current tcp ack no

	u32		Window;				// tcp window size (or scale for syn)
	u16		Flag;				// flags
	u16		CRC;				// checksum

} TCPEvent_t;

struct Output_t;
typedef struct Output_t Output_t;

struct TCPEventFilter {
	bool netRTT;
	bool appRTT;
	bool window;
};

u32 TCPEventDump(u8* OutputStr, Output_t* TCPOutput, u64 SnapshotTS, IP4Header_t* IP4, FlowRecord_t* FlowPkt, u32 TCPWindowScale);

#endif
