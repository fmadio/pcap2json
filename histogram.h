//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The Creative Commons BY-NC 4.0 International License see LICENSE file for details 
// 
// Histogram generation logic based on pcap
//
//---------------------------------------------------------------------------------------------

#ifndef _PCAP2JSON_HISTOGRAM_H__
#define _PCAP2JSON_HISTOGRAM_H__

typedef struct PacketInfo_t
{
	u32 	TSDiff;
	u16 	PktSize;
} __attribute__((packed)) PacketInfo_t;

typedef struct PacketInfoBulk_t
{
	u16						Max;
	u16						Pos;
	PacketInfo_t			*PktInfo;
	struct PacketInfoBulk_t	*Next;
} PacketInfoBulk_t;

#define SET_VLAN_BIT(H, VLANIdx)	((H)->VLAN = ((H)->VLAN | (1 << VLANIdx)))
#define GET_VLAN_BIT(H, VLANIdx)	(((H)->VLAN >> VLANIdx) & 1)
#define SET_MPLS_BIT(H, MPLSIdx)	((H)->MPLS = ((H)->MPLS | (1 << MPLSIdx)))
#define GET_MPLS_BIT(H, MPLSIdx)	(((H)->MPLS >> MPLSIdx) & 1)

#define HISTOGRAM_SIG_V1 0x01010101

typedef struct HistogramDump_t
{
	u32				signature;
	u32				FlowID;
	u16				MACProto;
	u8				IPProto;
	u8				IPDSCP;
	u8				VLAN:3;				// bits for VLAN0, VLAN1 and VLAN2
	u8				MPLS:3;				// bits for MPLS0, MPLS1 and MPLS2
	u8				Flags:2;			// unused for now
	u64				FirstTS;
	u64				TotalPkt;

	PacketInfo_t	pad[0];
} __attribute__((packed)) HistogramDump_t;

PacketInfoBulk_t* PktInfo_BulkAlloc(u32 MaxPkts);
void PktInfo_Insert(PacketInfoBulk_t **p, u16 Len, u64 Tdiff);
int PktInfo_HistogramPrint(FILE *FP, HistogramDump_t *H, PacketInfoBulk_t *P);

#endif
