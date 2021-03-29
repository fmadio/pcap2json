#include <stdio.h>
#include <string.h>
#include "fTypes.h"
#include "flow.h"

// For a 32-bit TCP event, the MSB (i.e. highest 8 bits) are for the flag mask,
// and the bottom 24 bits are for the TCP OP itself
enum TCP_OPS {
	TCP_OP_NULL,
	TCP_OP_SYN,
	TCP_OP_SYNACK,
	TCP_OP_ACK,
	TCP_OP_PSH,
	TCP_OP_RST,
	TCP_OP_FIN,
	TCP_OP_TOTAL_COUNT
};
char *TCP_OP_STR[TCP_OP_TOTAL_COUNT] = {
	"TCP_OP_NULL",

	"TCP_OP_SYN",
	"TCP_OP_SYNACK",
	"TCP_OP_ACK",
	"TCP_OP_PSH",
	"TCP_OP_RST",
	"TCP_OP_FIN"
};

#define TCP_OP_FLAG_MASK 0xff000000
#define TCP_OP_MASK ~TCP_OP_FLAG_MASK
#define TCP_OP_FLAG_BIT_SHIFT 24
enum TCP_OP_FLAG {
	TCP_OP_FLAG_H0 = 1,
	TCP_OP_FLAG_H1
};
char *TCP_OP_FLAG_STR[3] = {
	"NULL",

	"H0",
	"H1"
};


s8 FlowPktToTCPFullDup(FlowRecord_t* FlowPkt, TCPFullDup_t* TCPFullDup)
{
	TCPFullDup->IPProto = FlowPkt->IPProto;

	// Sort FlowPkt's MAC src-dst deterministically and set to TCPFullDup's A/B
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

u32 TCPEventDump(u8* OutputStr, u64 TS, IP4Header_t* IP4, FlowRecord_t* FlowPkt)
{
	// TODO: We want to at least output enough details for RTT to be calculated,
	// ideally much more (retransmissions/SACKs, window sizes, flow
	// control/congestion events, etc.)

	u32 IPOffset = (IP4->Version & 0x0f)*4;
	TCPHeader_t* TCP = (TCPHeader_t*)((u8*)IP4 + IPOffset);
	u16 TCPFlags = swap16(TCP->Flags);
	// A TCP event log includes an MSB for TCP_FLAG and the rest is TCP_OP
	u32 TCPEvent = TCP_OP_NULL;
	u8* Output = OutputStr;

	memset(Output, 0, strlen(Output));

	// TODO: Only one TCP event / packet? Or multiple based on flags/events?
	if (FlowPkt->IPProto == IPv4_PROTO_TCP)
	{
		// Set TCP OP
		if (TCP_FLAG_SYN(TCPFlags) == 1)
		{
			if (TCP_FLAG_ACK(TCPFlags) == 1)
				TCPEvent = TCP_OP_SYNACK;
			else
				TCPEvent = TCP_OP_SYN;
		}
		else if (FlowPkt->TCPLength == 0 && TCP_FLAG_ACK(TCPFlags) == 1)
		{
			TCPEvent = TCP_OP_ACK;
		}
		else if (FlowPkt->TCPLength != 0 && TCP_FLAG_ACK(TCPFlags) == 1)
		{
			TCPEvent = TCP_OP_PSH;
		}
		else if (TCP_FLAG_FIN(TCPFlags) == 1)
		{
			TCPEvent = TCP_OP_FIN;
		}
		else if (TCP_FLAG_RST(TCPFlags) == 1)
		{
			TCPEvent = TCP_OP_RST;
		}

		// Set MSB of TCP OP to directional flag
		TCPFullDup_t TCPFull = { 0 };
		s8 cmp = FlowPktToTCPFullDup(FlowPkt, &TCPFull);

		if (cmp > 0)
		{
			TCPEvent |= (TCP_OP_FLAG_H0 << TCP_OP_FLAG_BIT_SHIFT);
		}
		else
		{
			TCPEvent |= (TCP_OP_FLAG_H1 << TCP_OP_FLAG_BIT_SHIFT);
		}
	}

	u8 TCPOp = TCPEvent & TCP_OP_MASK;
	u8 TCPFlag = (TCPEvent & TCP_OP_FLAG_MASK) >> TCP_OP_FLAG_BIT_SHIFT;

	// TODO: Analyze TCP Options and log state change related info (window size, TS)

	if (TCPOp == TCP_OP_NULL)
	{
		// exit since there is no TCP OP to log
		return 0;
	}

	u8 TStr[128];
	FormatTSStr(TStr, TS);

	Output += sprintf(Output,
					  "{\"timestamp\":%f,\"TS\":\"%s\",\"tcp_op\":\"%s_%s\",\"seq\":%u,\"ack\":%u,\"len\":%u",
					  TS/1e6,
					  TStr,
					  TCP_OP_STR[TCPOp],
					  TCP_OP_FLAG_STR[TCPFlag],
					  TCP->SeqNo,
					  TCP->AckNo,
					  FlowPkt->TCPLength);

	Output += sprintf(Output,
					  ",\"hash_full_duplex\":\"%08x%08x%08x%08x%08x\"",
					  FlowPkt->SHA1FullDuplex[0],
					  FlowPkt->SHA1FullDuplex[1],
					  FlowPkt->SHA1FullDuplex[2],
					  FlowPkt->SHA1FullDuplex[3],
					  FlowPkt->SHA1FullDuplex[4]);

	Output += sprintf(Output, "}\n");

	assert(TCPOp != TCP_OP_NULL);
}
