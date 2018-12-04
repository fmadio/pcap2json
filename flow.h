#ifndef _PCAP2JSON_FLOW_H__
#define _PCAP2JSON_FLOW_H__

struct FlowRecord_t;

void Flow_Open				(void);
void Flow_Close				(struct Output_t* Out, u64 LastTS);
void Flow_DecodePacket		(struct Output_t* Out, u64 PacketTS, PCAPPacket_t* PktHeader);
void Flow_Stats				(u32* pFlowCntSnapShot);

#endif
