#include <stdio.h>
#include <string.h>
#include "fTypes.h"
#include "flow.h"

u32 TCPEventDump(u8* OutputStr, u64 TS, TCPHeader_t* tcp_header, FlowRecord_t* FlowPkt)
{
    // TODO: We want to at least output enough details for RTT to be calculated,
    // ideally much more (retransmissions/SACKs, window sizes, flow
    // control/congestion events, etc.)
    u8* Output = OutputStr;
    Output += sprintf(Output, "");
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
