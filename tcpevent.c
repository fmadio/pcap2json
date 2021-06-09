#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fTypes.h"
#include "output.h"
#include "flow.h"
#include "tcpevent.h"

extern struct TCPEventFilter g_TCPEventFilter;
extern u64 s_TotalEvents;

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

u32 TCPEventDump(u8* OutputStr, Output_t* TCPOutput, u64 SnapshotTS, IP4Header_t* IP4, FlowRecord_t* FlowPkt, u32 TCPWindowScale)
{
    // TODO: We want to at least output enough details for RTT to be calculated,
    // ideally much more (retransmissions/SACKs, window sizes, flow
    // control/congestion events, etc.)

    // Skip TCP events since no flags were set
    if (!g_Output_TCP_STDOUT && !g_Output_TCP_PipeName) return 0;

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
        if ((g_TCPEventFilter.netRTT || g_TCPEventFilter.window) && TCP_FLAG_SYN(TCPFlags) == 1)
        {
            if (TCP_FLAG_ACK(TCPFlags) == 1)
                TCPEvent = TCP_OP_SYNACK;
            else
                TCPEvent = TCP_OP_SYN;
        }
        else if ((g_TCPEventFilter.appRTT || g_TCPEventFilter.window) && FlowPkt->TCPLength != 0 && TCP_FLAG_ACK(TCPFlags) == 1)
        {
            TCPEvent = TCP_OP_PSH;
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
    FormatTSStr(TStr, SnapshotTS);

    if (!g_Output_TCP_STDOUT && g_Output_TCP_PipeName != NULL && TCPOutput)
    {
        TCPEvent_t tcp_output = { 0 };
        tcp_output.SnapshotTS = SnapshotTS;
        tcp_output.Event = TCPEvent;
        tcp_output.Length = FlowPkt->TCPLength;
        tcp_output.SeqNo = swap32(TCP->SeqNo);
        tcp_output.AckNo = swap32(TCP->AckNo);
        tcp_output.Flag = swap32(TCP->Flags);
        tcp_output.CRC = swap32(TCP->CSUM);
        memcpy(&tcp_output.HashFullDuplex, FlowPkt->SHA1Full, sizeof(FlowPkt->SHA1Full));

        if (TCP_FLAG_SYN(TCPFlags) == 1)
            tcp_output.Window = TCPWindowScale;
        else
            tcp_output.Window = swap16(TCP->Window);

        Output_BufferAdd(TCPOutput, (u8*) &tcp_output, sizeof(TCPEvent_t), 1);

        __sync_fetch_and_add(&s_TotalEvents, 1);
        return 1;
    }
    else
    {
        u32 window = (TCP_FLAG_SYN(TCPFlags) == 1) ? TCPWindowScale : swap16(TCP->Window);

        Output += sprintf(Output,
                          "{\"timestamp\":%llu,\"TS\":\"%s\",\"tcp_op\":\"%s_%s\",\"win\":%u,\"seq\":%u,\"ack\":%u,\"len\":%u",
                          SnapshotTS,
                          TStr,
                          TCP_OP_STR[TCPOp],
                          TCP_OP_FLAG_STR[TCPFlag],
                          window,
                          swap32(TCP->SeqNo),
                          swap32(TCP->AckNo),
                          FlowPkt->TCPLength);

        Output += sprintf(Output,
                          ",\"hash_full_duplex\":\"%08x%08x%08x%08x%08x\"",
                          swap32(FlowPkt->SHA1Full[0]),
                          swap32(FlowPkt->SHA1Full[1]),
                          swap32(FlowPkt->SHA1Full[2]),
                          swap32(FlowPkt->SHA1Full[3]),
                          swap32(FlowPkt->SHA1Full[4]));

        Output += sprintf(Output, "}\n");
        return 1;
    }

    assert(TCPOp != TCP_OP_NULL);
    return 0;
}
