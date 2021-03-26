#include <stdio.h>
#include <string.h>
#include "fTypes.h"
#include "flow.h"

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

u32 TCPEventDump(u8* OutputStr, u64 TS, IP4Header_t* IP4, FlowRecord_t* FlowPkt)
{
	// TODO: We want to at least output enough details for RTT to be calculated,
	// ideally much more (retransmissions/SACKs, window sizes, flow
	// control/congestion events, etc.)

	u32 IPOffset = (IP4->Version & 0x0f)*4;
	TCPHeader_t* TCP = (TCPHeader_t*)((u8*)IP4 + IPOffset);
	u16 TCPFlags = swap16(TCP->Flags);
	u8 TCPOp = TCP_OP_NULL;
	u8* Output = OutputStr;

	memset(Output, 0, strlen(Output));

	if (FlowPkt->IPProto == IPv4_PROTO_TCP)
	{
		if (TCP_FLAG_SYN(TCPFlags) == 1)
		{
			if (TCP_FLAG_ACK(TCPFlags) == 1)
				TCPOp = TCP_OP_SYNACK;
			else
				TCPOp = TCP_OP_SYN;
		}
		else if (FlowPkt->TCPLength == 0 && TCP_FLAG_ACK(TCPFlags) == 1)
		{
			TCPOp = TCP_OP_ACK;
		}
		else if (FlowPkt->TCPLength != 0 && TCP_FLAG_ACK(TCPFlags) == 1)
		{
			TCPOp = TCP_OP_PSH;
		}
		else if (TCP_FLAG_FIN(TCPFlags) == 1)
		{
			TCPOp = TCP_OP_FIN;
		}
		else if (TCP_FLAG_RST(TCPFlags) == 1)
		{
			TCPOp = TCP_OP_RST;
		}
	}

	// TODO: Analyze TCP Options and log state change related info (window size, TS)

	if (TCPOp == TCP_OP_NULL)
	{
		// exit since there is no TCP OP to log
		return 0;
	}

	u8 TStr[128];
	FormatTSStr(TStr, TS);

	Output += sprintf(Output,
					  "{\"timestamp\":%f,\"TS\":\"%s\",\"tcp_op\":\"%s\",\"seq\":%u,\"ack\":%u,\"len\":%u",
					  TS/1e6,
					  TStr,
					  TCP_OP_STR[TCPOp],
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

void FlowPktToTCPFullDup(FlowRecord_t* FlowPkt, TCPFullDup_t* TCPFullDup)
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
}
