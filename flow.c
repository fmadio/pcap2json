//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
// 
// guts of the flow calcuation. generats a SHA1 of the MAC/IP/Proto/Port
// and maps packets into this
//
// on the interop timecompressed(x100) + (192B sliced) data following performance is seen
//
// interop_scaled_20181204_2054     15GB Chunk(Cnt:   63842 Start: 4100250 End: 4164091 Comp:1.49) Inv:-nan Cap:-nan CacheI:-nan Cache:-nan Disk:-nan Drop:-nan Pkt:0
//
//
// 2018/12/07:   ~ 17Gbps ingress @ 43K flows per snapshot
//
// [11:54:56.639.887.104] Input:29.964 GB  17.00 Gbps PCAP: 248.85 Gbps | Output 0.27410 GB Flows/Snap:  42113 FlowCPU:0.617 | ESPush:       0  42.64K ESErr    0 | OutputCPU: 0.000
// [11:54:56.705.689.088] Input:31.911 GB  16.73 Gbps PCAP: 254.24 Gbps | Output 0.27439 GB Flows/Snap:  43165 FlowCPU:0.617 | ESPush:       0   0.53K ESErr    0 | OutputCPU: 0.000
// [11:54:56.768.221.696] Input:33.900 GB  17.09 Gbps PCAP: 273.26 Gbps | Output 0.29819 GB Flows/Snap:  43591 FlowCPU:0.619 | ESPush:       0  43.59K ESErr    0 | OutputCPU: 0.000
// [11:54:56.831.990.784] Input:35.886 GB  17.05 Gbps PCAP: 267.44 Gbps | Output 0.31004 GB Flows/Snap:  43591 FlowCPU:0.616 | ESPush:       0  22.04K ESErr    0 | OutputCPU: 0.000
//
// test configuration
//	--cpu 23
//	--json-flow
//	--es-host 192.168.2.115:9200
//	--output-null
//	--output-timeflush 1e9
//	--capture-name pcap2json_test
//	--flow-samplerate 100e6
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <locale.h>
#include <linux/sched.h>
#include <pthread.h>

#include "fTypes.h"
#include "fProfile.h"
#include "output.h"
#include "flow.h"

void sha1_compress(uint32_t state[static 5], const uint8_t block[static 64]);

//---------------------------------------------------------------------------------------------

typedef struct FlowRecord_t 
{
	u16						EtherProto;			// ethernet protocol
	u8						EtherSrc[6];		// ethernet src mac
	u8						EtherDst[6];		// ethernet dst mac

	u16						VLAN[4];			// vlan tags
	u16						MPLS[4];			// MPLS tags
	u16						MPLStc[4];			// MPLS traffic class 

	u8						IPSrc[4];			// source IP
	u8						IPDst[4];			// source IP

	u8						IPProto;			// IP protocol

	u16						PortSrc;			// tcp/udp port source
	u16						PortDst;			// tcp/udp port source

	u8						pad[17];			// SHA1 calcuated on the first 64B

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

	//-------------------------------------------------------------------------------
	
	u32						SHA1[5];			// SHA of the flow

	u64						FirstTS;			// first TS seen
	u64						LastTS;				// last TS seen 

	u64						TotalPkt;			// total packets
	u64						TotalByte;			// total bytes

	TCPHeader_t				TCPHeader;			// copy of the TCP Header

	struct FlowRecord_t*	Next;				// next flow record
	struct FlowRecord_t*	Prev;				// previous flow record

} __attribute__((packed)) FlowRecord_t;

// top level flow index
typedef struct FlowIndex_t
{
	u64						FlowMax;			// maximum number of flows 
	FlowRecord_t*			FlowList;			// list of statically allocated flows
	FlowRecord_t**			FlowHash;			// flash hash index
	u32						FlowLock;			// mutex to modify 

	u64						FlowCntSnapshot;	// number of flows in this snapshot

} FlowIndex_t;

//---------------------------------------------------------------------------------------------
// command line parameters, see main.c for descriptions
extern bool				g_IsJSONPacket;
extern bool				g_IsJSONFlow;

extern bool				g_JSONEnb_MAC;
extern bool				g_JSONEnb_VLAN;
extern bool				g_JSONEnb_MPLS;
extern bool				g_JSONEnb_IPV4;
extern bool				g_JSONEnb_UDP;
extern bool				g_JSONEnb_TCP;

extern  s64				g_FlowSampleRate;

extern u8 				g_CaptureName[256];
extern u8				g_DeviceName[128];

//---------------------------------------------------------------------------------------------
// static

static u32						s_FlowIndexMax		= 4;
static u32						s_FlowIndexPos		= 0;
static u32						s_FlowIndexMsk		= 3;
static FlowIndex_t				s_FlowIndex[4];
static u32						s_FlowCntSnapshotLast = 0;				// last total flows in the last snapshot

static u64						s_FlowCntTotal		= 0;				// total number of active flows

static u32						s_PacketBufferMax	= 2048;				// max number of inflight packets
static PacketBuffer_t			s_PacketBufferList[2048];				// list of header structs for each buffer^
static volatile PacketBuffer_t*	s_PacketBuffer		= NULL;				// linked list of free packet buffers
static u32						s_PacketBufferLock	= 0;

static u32						s_DecodeCPUActive 	= 0;				// total number of active decode threads
static pthread_t   				s_DecodeThread[16];						// worker decode thread list
static u64						s_DecodeThreadTSCTop[128];				// total cycles
static u64						s_DecodeThreadTSCDecode[128];			// total cycles for decoding

static volatile u32				s_DecodeQueuePut 	= 0;				// put/get processing queue
static volatile u32				s_DecodeQueueGet 	= 0;
static u32						s_DecodeQueueMsk 	= 1023;
static volatile PacketBuffer_t*	s_DecodeQueue[1024];					// list of packets pending processing

static struct Output_t*			s_Output			= NULL;				// output module

static u64						s_PacketQueueCnt	= 0;
static u64						s_PacketDecodeCnt	= 0;

//---------------------------------------------------------------------------------------------
// generate a 20bit hash index 
static u32 HashIndex(u32* SHA1)
{
	u8* Data8 = (u8*)SHA1;

	// FNV1a 80b hash 
	const u32 Prime  = 0x01000193; //   16777619
	const u32  Seed  = 0x811C9DC5; // 2166136261

	u32 Hash = Seed;
	Hash = ((u32)Data8[ 0] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 1] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 2] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 3] ^ Hash) * Prime;

	Hash = ((u32)Data8[ 4] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 5] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 6] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 7] ^ Hash) * Prime;

	Hash = ((u32)Data8[ 8] ^ Hash) * Prime;
	Hash = ((u32)Data8[ 9] ^ Hash) * Prime;
	Hash = ((u32)Data8[10] ^ Hash) * Prime;
	Hash = ((u32)Data8[11] ^ Hash) * Prime;

	Hash = ((u32)Data8[12] ^ Hash) * Prime;
	Hash = ((u32)Data8[13] ^ Hash) * Prime;
	Hash = ((u32)Data8[14] ^ Hash) * Prime;
	Hash = ((u32)Data8[15] ^ Hash) * Prime;

	Hash = ((u32)Data8[16] ^ Hash) * Prime;
	Hash = ((u32)Data8[17] ^ Hash) * Prime;
	Hash = ((u32)Data8[18] ^ Hash) * Prime;
	Hash = ((u32)Data8[19] ^ Hash) * Prime;

	// reduce down to 20bits for set/way index
	return (Hash & 0x000fffff) ^ (Hash >> 20);
}

//---------------------------------------------------------------------------------------------

static FlowRecord_t* FlowAlloc(FlowIndex_t* FlowIndex, FlowRecord_t* F)
{
	assert(FlowIndex->FlowCntSnapshot < FlowIndex->FlowMax);

	FlowRecord_t* Flow = &FlowIndex->FlowList[ FlowIndex->FlowCntSnapshot++ ]; 
	memset(Flow, 0, sizeof(FlowRecord_t) );

	// copy flow values, leaving the counters reset at zero 
	memcpy(Flow, F, offsetof(FlowRecord_t, pad));

	// copy per packet state
	Flow->TCPLength = F->TCPLength;

	return Flow;
}

//---------------------------------------------------------------------------------------------
// clear out the flow records 
static void FlowReset(FlowIndex_t* FlowIndex)
{
	memset(FlowIndex->FlowHash, 0, sizeof(FlowRecord_t*) * (2 << 20) );

	// save last count for stats
	s_FlowCntSnapshotLast = FlowIndex->FlowCntSnapshot;

	FlowIndex->FlowCntSnapshot = 0;
}

//---------------------------------------------------------------------------------------------
// assumption is this is mutually exclusive per FlowIndex
static void FlowInsert(FlowIndex_t* FlowIndex, FlowRecord_t* FlowPkt, u32* SHA1, u32 Length, u64 TS)
{
	u32 Index = HashIndex(SHA1);

	FlowRecord_t* F = NULL;
	bool IsFlowNew = false;

	// first record ?
	if (FlowIndex->FlowHash[ Index ] == NULL)
	{
		F = FlowAlloc(FlowIndex, FlowPkt);

		F->SHA1[0] = SHA1[0];
		F->SHA1[1] = SHA1[1];
		F->SHA1[2] = SHA1[2];
		F->SHA1[3] = SHA1[3];
		F->SHA1[4] = SHA1[4];

		F->Next		= NULL;
		F->Prev		= NULL;

		FlowIndex->FlowHash[Index] = F;

		IsFlowNew = true;
	}
	else
	{
		F = FlowIndex->FlowHash[ Index ];

		// iterate in search of the flow
		FlowRecord_t* FPrev = NULL;
		while (F)
		{
			bool IsHit = true;

			IsHit &= (F->SHA1[0] == SHA1[0]);
			IsHit &= (F->SHA1[1] == SHA1[1]);
			IsHit &= (F->SHA1[2] == SHA1[2]);
			IsHit &= (F->SHA1[3] == SHA1[3]);
			IsHit &= (F->SHA1[4] == SHA1[4]);

			if (IsHit)
			{
				break;
			}

			FPrev = F;
			F = F->Next;
		}

		// new flow
		if (!F)
		{
			F = FlowAlloc(FlowIndex, FlowPkt);

			F->SHA1[0] = SHA1[0];
			F->SHA1[1] = SHA1[1];
			F->SHA1[2] = SHA1[2];
			F->SHA1[3] = SHA1[3];
			F->SHA1[4] = SHA1[4];

			F->Next		= NULL;
			F->Prev		= NULL;

			FPrev->Next = F;
			F->Prev		= FPrev;

			IsFlowNew	= true;
		}
	}

	if (IsFlowNew)
	{
		s_FlowCntTotal++;
	}

	// update flow stats
	F->TotalPkt		+= 1;
	F->TotalByte	+= Length;
	F->FirstTS		= (F->FirstTS == 0) ? TS : F->FirstTS;
	F->LastTS		=  TS;

	if (F->IPProto == IPv4_PROTO_TCP)
	{
		// update TCP Flag counts
		TCPHeader_t* TCP = &FlowPkt->TCPHeader; 
		u16 TCPFlags = swap16(TCP->Flags);
		F->TCPFINCnt	+= (TCP_FLAG_FIN(TCPFlags) != 0);
		F->TCPSYNCnt	+= (TCP_FLAG_SYN(TCPFlags) != 0);
		F->TCPRSTCnt	+= (TCP_FLAG_RST(TCPFlags) != 0);
		F->TCPPSHCnt	+= (TCP_FLAG_PSH(TCPFlags) != 0);
		F->TCPACKCnt	+= (TCP_FLAG_ACK(TCPFlags) != 0);

		// check for re-transmits
		// works by checking for duplicate 0 payload acks
		// of an ack no thats already been seen. e.g. tcp fast re-transmit request
		// https://en.wikipedia.org/wiki/TCP_congestion_control#Fast_retransmit
		// 
		// 2018/12/04: SACK traffic messes this up
		if (TCP_FLAG_ACK(TCPFlags))
		{
			u32 TCPAckNo	= swap32(TCP->AckNo);
			if ((FlowPkt->TCPLength == 0) && (F->TCPAckNo == TCPAckNo))
			{
				// if its not a SACK
				if (!FlowPkt->TCPIsSACK)
				{
					F->TCPSACKCnt	+= 1; 
				}
				else
				{
					F->TCPACKDupCnt	+= 1; 
				}
				//if (F->PortSrc == 49279)
				//{
				//	printf("[%s] seqno dup: %u %i %i : %i %i %i %i -> %i %i %i %i\n", 
				//		FormatTS(TS),
				//			TCPAckNo, F->TCPLength, FlowPkt->TCPLength, F->IPSrc[0], F->IPSrc[1], F->IPSrc[2], F->IPSrc[3], F->IPDst[0], F->IPDst[1], F->IPDst[2], F->IPDst[3] );
				//}
			}
			F->TCPAckNo = TCPAckNo;
		}

		// first packet
		u32 TCPWindow = swap16(TCP->Window); 
		if (F->TotalPkt == 1)
		{
			F->TCPWindowMin = TCPWindow; 
			F->TCPWindowMax = TCPWindow; 
		}
		F->TCPWindowMin = (F->TCPWindowMin > TCPWindow) ? TCPWindow : F->TCPWindowMin;
		F->TCPWindowMax = (F->TCPWindowMax < TCPWindow) ? TCPWindow : F->TCPWindowMax;
	}
}

//---------------------------------------------------------------------------------------------
// write a flow record out as a JSON file
// this is designed for ES bulk data upload using the 
// mappings.json file as the index 
static u32 FlowDump(struct Output_t* Out, u64 TS, FlowRecord_t* Flow, u32 FlowID) 
{

	u8 OutputStr[1024];
	u8* Output 		= OutputStr;
	u8* OutputStart = Output;

	// ES header for bulk upload
	Output += sprintf(Output, "{\"index\":{\"_index\":\"%s\",\"_type\":\"flow_record\",\"_score\":null}}\n", g_CaptureName);

	// actual payload
	Output += sprintf(Output, "{\"timestamp\":%f,\"TS\":\"%s\",\"FlowCnt\":%lli,\"Device\":\"%s\"", TS/1e6, FormatTS(TS), FlowID, g_DeviceName);

	// print flow info
	Output += sprintf(Output, ",\"hash\":\"%08x%08x%08x%08x%08x\"",	Flow->SHA1[0],
																	Flow->SHA1[1],
																	Flow->SHA1[2],
																	Flow->SHA1[3],
																	Flow->SHA1[4]);

	if (g_JSONEnb_MAC)
	{
		Output += sprintf(Output, ",\"MACSrc\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"MACDst\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",

															Flow->EtherSrc[0],
															Flow->EtherSrc[1],
															Flow->EtherSrc[2],
															Flow->EtherSrc[3],
															Flow->EtherSrc[4],
															Flow->EtherSrc[5],

															Flow->EtherDst[0],
															Flow->EtherDst[1],
															Flow->EtherDst[2],
															Flow->EtherDst[3],
															Flow->EtherDst[4],
															Flow->EtherDst[5]
		);

		// output human readable Ether protocol info
		u8 MACProto[128];
		switch (Flow->EtherProto)
		{
		case ETHER_PROTO_ARP:
			strcpy(MACProto, "ARP");
			break;
		case ETHER_PROTO_IPV4:
			strcpy(MACProto, "IPv4");
			break;
		case ETHER_PROTO_IPV6:
			strcpy(MACProto, "IPv6");
			break;
		case ETHER_PROTO_VLAN:
			strcpy(MACProto, "VLAN");
			break;
		case ETHER_PROTO_VNTAG:
			strcpy(MACProto, "VNTAG");
			break;
		case ETHER_PROTO_MPLS:
			strcpy(MACProto, "MPLS");
			break;
		default:
			sprintf(MACProto, "%04x", Flow->EtherProto);
			break;
		}
		Output += sprintf(Output, ",\"MACProto\":\"%s\"", MACProto); 
	}

	// print VLAN is valid
	if (g_JSONEnb_VLAN)
	{
		if (Flow->VLAN[0] != 0)
		{
			Output += sprintf(Output, ",\"VLAN.0\":%i",  Flow->VLAN[0]);
		}
		if (Flow->VLAN[1] != 0)
		{
			Output += sprintf(Output, ",\"VLAN.1\":%i",  Flow->VLAN[1]);
		}
	}

	// print MPLS info
	if (g_JSONEnb_MPLS)
	{
		if (Flow->MPLS[0])
		{
			Output += sprintf(Output, ",\"MPLS.0.Label\":%i, \"MPLS.0.TC\":%i",  Flow->MPLS[0], Flow->MPLStc[0]);
		}
		if (Flow->MPLS[1])
		{
			Output += sprintf(Output, ",\"MPLS.1.Label\":%i, \"MPLS.1.TC\":%i",  Flow->MPLS[1], Flow->MPLStc[1]);
		}
	}

	// IPv4 proto info
	if (Flow->EtherProto ==  ETHER_PROTO_IPV4)
	{
		if (g_JSONEnb_IPV4)
		{
			Output += sprintf(Output, ",\"IPv4.Src\":\"%i.%i.%i.%i\",\"IPv4.Dst\":\"%i.%i.%i.%i\" ",
												Flow->IPSrc[0],
												Flow->IPSrc[1],
												Flow->IPSrc[2],
												Flow->IPSrc[3],

												Flow->IPDst[0],
												Flow->IPDst[1],
												Flow->IPDst[2],
												Flow->IPDst[3]
			);

			// convert to readable names for common protocols 
			u8 IPProto[128];
			switch (Flow->IPProto) 
			{
			case IPv4_PROTO_UDP:	strcpy(IPProto, "UDP");		break;
			case IPv4_PROTO_TCP:	strcpy(IPProto, "TCP");		break;
			case IPv4_PROTO_IGMP:	strcpy(IPProto, "IGMP"); 	break;
			case IPv4_PROTO_ICMP:	strcpy(IPProto, "ICMP"); 	break;
			case IPv4_PROTO_GRE:	strcpy(IPProto, "GRE"); 	break;
			case IPv4_PROTO_VRRP:	strcpy(IPProto, "VRRP"); 	break;
			default:
				sprintf(IPProto, "%02x", Flow->IPProto);
				break;
			}
			Output += sprintf(Output, ",\"IPv4.Proto\":\"%s\"", IPProto);
		}

		// per protocol info
		switch (Flow->IPProto)
		{
		case IPv4_PROTO_UDP:
		{
			if (g_JSONEnb_UDP)
			{
				Output += sprintf(Output, ",\"UDP.Port.Src\":%i,\"UDP.Port.Dst\":%i",
													Flow->PortSrc,
													Flow->PortDst	
				);
			}
		}
		break;

		case IPv4_PROTO_TCP:
		{
			if (g_JSONEnb_TCP)
			{
				if (g_IsJSONPacket)
				{
					TCPHeader_t* TCP = &Flow->TCPHeader; 
					u16 Flags = swap16(TCP->Flags);
					Output += sprintf(Output,",\"TCP.SeqNo\":%u,\"TCP.AckNo\":%u,\"TCP.FIN\":%i,\"TCP.SYN\":%i,\"TCP.RST\":%i,\"TCP.PSH\":%i,\"TCP.ACK\":%i,\"TCP.Window\":%i",
							swap32(TCP->SeqNo),
							swap32(TCP->AckNo),
							TCP_FLAG_FIN(Flags),
							TCP_FLAG_SYN(Flags),
							TCP_FLAG_RST(Flags),
							TCP_FLAG_PSH(Flags),
							TCP_FLAG_ACK(Flags),
							swap16(TCP->Window)
					);
				}
				else
				{
					Output += sprintf(Output,",\"TCP.FIN\":%i,\"TCP.SYN\":%i,\"TCP.RST\":%i,\"TCP.PSH\":%i,\"TCP.ACK\":%i,\"TCP.WindowMin\":%i,\"TCP.WindowMax\":%i,\"TCP.ACKDup\":%i,\"TCP.SACK\":%i",
							Flow->TCPFINCnt,
							Flow->TCPSYNCnt,
							Flow->TCPRSTCnt,
							Flow->TCPPSHCnt,
							Flow->TCPACKCnt,
							Flow->TCPWindowMin,
							Flow->TCPWindowMax,
							Flow->TCPACKDupCnt,
							Flow->TCPSACKCnt
					);
				}
				Output += sprintf(Output, ",\"TCP.Port.Src\":%i,\"TCP.Port.Dst\":%i",
											Flow->PortSrc,
											Flow->PortDst	
				);
			}
		}
		break;
		}
	}

	Output += sprintf(Output, ",\"TotalPkt\":%lli,\"TotalByte\":%lli,\"TotalBits\":%lli",
									Flow->TotalPkt,
									Flow->TotalByte,
									Flow->TotalByte*8ULL
	);

	Output += sprintf(Output, "}\n");

	u32 OutputLen = Output - OutputStart;

	// write to output
	Output_LineAdd(Out, OutputStart, OutputLen);
}


//---------------------------------------------------------------------------------------------
//
// parse a packet and generate a flow record 
//
void DecodePacket(struct Output_t* Out, PacketBuffer_t* Pkt)
{
	u64 PacketTS 			= Pkt->TS;
	PCAPPacket_t* PktHeader = (PCAPPacket_t*)Pkt->Buffer;

	FlowRecord_t	sFlow;	
	FlowRecord_t*	FlowPkt = &sFlow;	
	memset(FlowPkt, 0, sizeof(FlowRecord_t));

	// assume single packet flow
	FlowPkt->TotalPkt	 	= 1;
	FlowPkt->TotalByte 	= PktHeader->LengthWire;

	// ether header info
	fEther_t* Ether = (fEther_t*)(PktHeader + 1);	
	u8* Payload 	= (u8*)(Ether + 1);
	u16 EtherProto 	= swap16(Ether->Proto);

	FlowPkt->EtherProto	= EtherProto;
	FlowPkt->EtherSrc[0]	= Ether->Src[0];
	FlowPkt->EtherSrc[1]	= Ether->Src[1];
	FlowPkt->EtherSrc[2]	= Ether->Src[2];
	FlowPkt->EtherSrc[3]	= Ether->Src[3];
	FlowPkt->EtherSrc[4]	= Ether->Src[4];
	FlowPkt->EtherSrc[5]	= Ether->Src[5];

	FlowPkt->EtherDst[0]	= Ether->Dst[0];
	FlowPkt->EtherDst[1]	= Ether->Dst[1];
	FlowPkt->EtherDst[2]	= Ether->Dst[2];
	FlowPkt->EtherDst[3]	= Ether->Dst[3];
	FlowPkt->EtherDst[4]	= Ether->Dst[4];
	FlowPkt->EtherDst[5]	= Ether->Dst[5];
	
	// VLAN decoder
	if (EtherProto == ETHER_PROTO_VLAN)
	{
		VLANTag_t* Header 	= (VLANTag_t*)(Ether+1);
		u16* Proto 			= (u16*)(Header + 1);

		// update to the acutal proto / ipv4 header
		EtherProto 			= swap16(Proto[0]);
		Payload 			= (u8*)(Proto + 1);

		// first vlan tag
		FlowPkt->VLAN[0]		= VLANTag_ID(Header);

		// VNTag unpack (BME) 
		if (EtherProto == ETHER_PROTO_VNTAG)
		{
			VNTag_t* Header = (VNTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);
		}

		// is it double tagged ? 
		if (EtherProto == ETHER_PROTO_VLAN)
		{
			Header 			= (VLANTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);

			// 2nd vlan tag
			FlowPkt->VLAN[1]		= VLANTag_ID(Header);
		}
	}

	// MPLS decoder	
	if (EtherProto == ETHER_PROTO_MPLS)
	{
		MPLSHeader_t* MPLS = (MPLSHeader_t*)(Payload);

		u32 MPLSDepth = 0;

		// first MPLS 
		FlowPkt->MPLS[0]		= MPLS_LABEL(MPLS);
		FlowPkt->MPLStc[0]		= MPLS->TC;

		// for now only process outer tag
		// assume there is a sane limint on the encapsulation count
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// seccond 
			FlowPkt->MPLS[1]		= MPLS_LABEL(MPLS);
			FlowPkt->MPLStc[1]		= MPLS->TC;
		}
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// third 
			FlowPkt->MPLS[2]		= MPLS_LABEL(MPLS);
			FlowPkt->MPLStc[2]		= MPLS->TC;
		}
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// fourth 
			FlowPkt->MPLS[3]		= MPLS_LABEL(MPLS);
			FlowPkt->MPLStc[3]		= MPLS->TC;
		}

		// update to next header
		if (MPLS->BOS)
		{
			EtherProto = ETHER_PROTO_IPV4;
			Payload = (u8*)(MPLS + 1);
		}
	}

	// update final ethernet protocol
	FlowPkt->EtherProto	= EtherProto;

	// ipv4 info
	if (EtherProto == ETHER_PROTO_IPV4)
	{
		IP4Header_t* IP4 = (IP4Header_t*)Payload;

		FlowPkt->IPSrc[0] = IP4->Src.IP[0];	
		FlowPkt->IPSrc[1] = IP4->Src.IP[1];	
		FlowPkt->IPSrc[2] = IP4->Src.IP[2];	
		FlowPkt->IPSrc[3] = IP4->Src.IP[3];	

		FlowPkt->IPDst[0] = IP4->Dst.IP[0];	
		FlowPkt->IPDst[1] = IP4->Dst.IP[1];	
		FlowPkt->IPDst[2] = IP4->Dst.IP[2];	
		FlowPkt->IPDst[3] = IP4->Dst.IP[3];	

		FlowPkt->IPProto = IP4->Proto;

		// IPv4 protocol decoders 
		u32 IPOffset = (IP4->Version & 0x0f)*4; 
		switch (IP4->Proto)
		{
		case IPv4_PROTO_TCP:
		{
			TCPHeader_t* TCP = (TCPHeader_t*)(Payload + IPOffset);

			FlowPkt->PortSrc	= swap16(TCP->PortSrc);
			FlowPkt->PortDst	= swap16(TCP->PortDst);

			// make a copy of the tcp header 
			FlowPkt->TCPHeader = TCP[0];

			// payload length
			u32 TCPOffset = ((TCP->Flags&0xf0)>>4)*4;
			FlowPkt->TCPLength =  swap16(IP4->Len) - IPOffset - TCPOffset;

			// check for options
			if (TCPOffset > 20)
			{
				bool IsDone = false;
				u8* Options = (u8*)(TCP + 1);	
				while ( (Options - (u8*)TCP) < TCPOffset) 
				{
					if (IsDone) break;

					u32 Cmd = Options[0];
					u32 Len = Options[1];

					switch (Cmd)
					{
					// end of list 
					case 0x0:
						IsDone = true;
						break;

					// NOP 
					case 0x1: break;

					// MSS
					case 0x2: break;

					// Window Scale
					case 0x3:
						//printf("Window Scale: %i\n", Options[2]);
						FlowPkt->TCPWindowScale = Options[2];
						break;

					// SACK
					case 0x5:
						FlowPkt->TCPIsSACK = true;
						break;

					// TSOpt
					case 0x8: 
						//printf("TCP Option TS\n");
						break;

					default:
						//printf("option: %i : %i\n", Cmd, Len); 
						break;
					}
					Options += 1 + Len;
				}
			}
		}
		break;
		case IPv4_PROTO_UDP:
		{
			UDPHeader_t* UDP = (UDPHeader_t*)(Payload + IPOffset);

			FlowPkt->PortSrc	= swap16(UDP->PortSrc);
			FlowPkt->PortDst	= swap16(UDP->PortDst);
		}
		break;
		}
	}

	// generate SHA1
	// nice way to grab all packets for a single flow, search for the sha1 hash	
	// NOTE: FlowPktRecord_t setup so the first 64B contains only the flow info
	//       with packet and housekeeping info stored after. sha1_compress
	//       runs on the first 64B only 

	u32 SHA1State[5] = { 0, 0, 0, 0, 0 };
	sha1_compress(SHA1State, (u8*)FlowPkt);

	FlowPkt->SHA1[0] = SHA1State[0];
	FlowPkt->SHA1[1] = SHA1State[1];
	FlowPkt->SHA1[2] = SHA1State[2];
	FlowPkt->SHA1[3] = SHA1State[3];
	FlowPkt->SHA1[4] = SHA1State[4];

	// packet mode then print record as a packet 
	if (g_IsJSONPacket)
	{
		FlowDump(Out, PacketTS, FlowPkt, 0);
	}

	// update the flow records
	if (g_IsJSONFlow)
	{
		// assigned index to add the packet to
		FlowIndex_t* FlowIndex = Pkt->FlowIndex; 

		// insert to flow table
		// NOTE: lock around it so therems no RMW problems
		//       with the hash overflow list, and also the counters
		//       on output ensure no one modifies the 
		//       specific flow index instance while its beeing dumped 
		sync_lock(&FlowIndex->FlowLock, 100);
		{
			FlowInsert(FlowIndex, FlowPkt, SHA1State, PktHeader->LengthWire, PacketTS);

			// flow snapshot dump triggered by Flow_PacketQueue
			// as its serialized and single threaded
			if (Pkt->IsFlowIndexDump)
			{
				for (int i=0; i < FlowIndex->FlowCntSnapshot; i++)
				{
					FlowRecord_t* Flow = &FlowIndex->FlowList[i];	
					FlowDump(Out, PacketTS, Flow, i);
				}

				// reset index and counts
				FlowReset(FlowIndex);
			}
		}
		sync_unlock(&FlowIndex->FlowLock);
	}
}

//---------------------------------------------------------------------------------------------
// queue a packet for processing 
void Flow_PacketQueue(PacketBuffer_t* Pkt)
{
	// multi-core version
	{
		// wait for space int he queue 
		fProfile_Start(1, "FlowQueueStall");
		while (((s_DecodeQueuePut + 8) & s_DecodeQueueMsk) == (s_DecodeQueueGet & s_DecodeQueueMsk))
		{
			//ndelay(100);
			usleep(0);
		}
		fProfile_Stop(1);

		// add to processing queue
		u32 Index 				= s_DecodeQueuePut & s_DecodeQueueMsk;
		s_DecodeQueue[Index] 	= Pkt;

		// flow index
		Pkt->IsFlowIndexDump	 = false;
		Pkt->FlowIndex			 = &s_FlowIndex[s_FlowIndexPos];

		// purge the flow records every 100msec
		// as this is the singled threaded serialized
		// entry point, can flag it here instead of
		// in the worker threads
		static u64 LastPacketTS = 0;
		s64 dTS = Pkt->TS - LastPacketTS;
		if (dTS > g_FlowSampleRate)
		{
			LastPacketTS 			= Pkt->TS;
			Pkt->IsFlowIndexDump	 = true;

			// next flow structure. means all the  
			// flow workers dont get blocked when an flow dump
			// is triggered. as the mutual exclusion locks are
			// per flow index
			//
			// no need for flow control, as there are more flow indexs
			// than there are worker threads
			s_FlowIndexPos 			= (s_FlowIndexPos + 1) & s_FlowIndexMsk;
		}

		s_DecodeQueuePut++;
		s_PacketQueueCnt++;
	}
/*
	// single cpu
	{
		DecodePacket(s_Output, Pkt);
		Flow_PacketFree(Pkt);
	}	
*/
}

//---------------------------------------------------------------------------------------------

void* Flow_Worker(void* User)
{
	u32 CPUID = __sync_fetch_and_add(&s_DecodeCPUActive, 1);

	printf("Start decoder thread: %i\n", CPUID);
	while (true)
	{
		u64 TSC0 = rdtsc();

		u32 Get = s_DecodeQueueGet;
		if (Get == s_DecodeQueuePut)
		{
			// nothing to do
			//ndelay(1000);
			usleep(0);
		}
		else
		{
			if (__sync_bool_compare_and_swap(&s_DecodeQueueGet, Get, Get + 1))
			{
				u32 Index = Get & s_DecodeQueueMsk;

				u64 TSC2 = rdtsc();

				PacketBuffer_t* Pkt = (PacketBuffer_t*)s_DecodeQueue[Index];
				DecodePacket(s_Output, Pkt);

				// release buffer
				Flow_PacketFree(Pkt);

				// update counter
				__sync_fetch_and_add(&s_PacketDecodeCnt, 1);

				u64 TSC3 = rdtsc();
				s_DecodeThreadTSCDecode[CPUID] += TSC3 - TSC2;
			}
		}

		u64 TSC1 = rdtsc();
		s_DecodeThreadTSCTop[CPUID] += TSC1 - TSC0;
	}
}

//---------------------------------------------------------------------------------------------
// packet buffer management 
PacketBuffer_t* Flow_PacketAlloc(void)
{
	// stall waiting for free buffer
	u32 Timeout = 0;
	while (true)
	{
		if (s_PacketBuffer != NULL) break;

		usleep(0);
		//ndelay(100);
		assert(Timeout++ < 1e6);
	}

	// acquire lock
	PacketBuffer_t* B = NULL; 
	sync_lock(&s_PacketBufferLock, 50);
	{
		B = (PacketBuffer_t*)s_PacketBuffer;
		assert(B != NULL);

		s_PacketBuffer = B->FreeNext;

		// release lock
		assert(s_PacketBufferLock == 1); 
	}
	sync_unlock(&s_PacketBufferLock);

	// double check its a valid free pkt
	assert(B->IsUsed == false);
	B->IsUsed = true;

	return B;
}

void Flow_PacketFree(PacketBuffer_t* B)
{
	// acquire lock
	sync_lock(&s_PacketBufferLock, 100); 
	{
		// push at head
		B->FreeNext 	= (PacketBuffer_t*)s_PacketBuffer;
		s_PacketBuffer 	= B;

		B->IsUsed = false;

		// release lock
		assert(s_PacketBufferLock == 1); 
	}
	sync_unlock(&s_PacketBufferLock);
}

//---------------------------------------------------------------------------------------------
// allocate memory and house keeping
void Flow_Open(struct Output_t* Out)
{
	s_Output = Out;
	assert(s_Output != NULL);

	// allocate packet buffers
	for (int i=0; i < s_PacketBufferMax; i++)
	{
		PacketBuffer_t* B = &s_PacketBufferList[i];
		memset(B, 0, sizeof(PacketBuffer_t));

		B->BufferMax 	= 16*1024;
		B->Buffer 		= malloc(B->BufferMax);
		memset(B->Buffer, 0, B->BufferMax);	

		Flow_PacketFree(B);
	}

	// allocate flow indexes
	for (int i=0; i < s_FlowIndexMax; i++)
	{
		FlowIndex_t* FlowIndex = &s_FlowIndex[i];

		// max out at 1M flows
		FlowIndex->FlowMax	= 1024*1024;

		// allocate and clear flow index
		FlowIndex->FlowHash = (FlowRecord_t **)malloc( sizeof(FlowRecord_t *) * (2 << 20) );
		assert(FlowIndex->FlowHash != NULL);

		// allocate statically allocated flow list
		FlowIndex->FlowList = (FlowRecord_t *)malloc (sizeof(FlowRecord_t) * FlowIndex->FlowMax );
		assert(FlowIndex->FlowList != NULL);

		// reset flow info
		FlowReset(FlowIndex);
	}

	// create worker threads
	u32 CPUCnt = 0;
	pthread_create(&s_DecodeThread[0], NULL, Flow_Worker, (void*)NULL); CPUCnt++;
	pthread_create(&s_DecodeThread[1], NULL, Flow_Worker, (void*)NULL); CPUCnt++;
	//pthread_create(&s_DecodeThread[2], NULL, Flow_Worker, (void*)NULL); CPUCnt++;
	//pthread_create(&s_DecodeThread[3], NULL, Flow_Worker, (void*)NULL); CPUCnt++;

	u32 CPUMap[8] = { 19, 20, 21, 22 };
	for (int i=0; i < CPUCnt; i++)
	{
		cpu_set_t Thread0CPU;
		CPU_ZERO(&Thread0CPU);
		CPU_SET (CPUMap[i], &Thread0CPU);
		pthread_setaffinity_np(s_DecodeThread[i], sizeof(cpu_set_t), &Thread0CPU);
	}
}

//---------------------------------------------------------------------------------------------
// shutdown / flush
void Flow_Close(struct Output_t* Out, u64 LastTS)
{
	// wait for all queues to drain
	u32 Timeout = 0;
	while (s_DecodeQueuePut != s_DecodeQueueGet)
	{
		usleep(0);
		assert(Timeout++ < 1e6);
	}

	// output last flow data
	if (g_IsJSONFlow)
	{
		for (int j=0; j < s_FlowIndexMax; j++)
		{
			FlowIndex_t* FlowIndex = &s_FlowIndex[j];
			for (int i=0; i < FlowIndex->FlowCntSnapshot; i++)
			{
				FlowRecord_t* Flow = &FlowIndex->FlowList[i];	
				FlowDump(Out, LastTS, Flow, i);
			}
			printf("Total Flows: %i\n", FlowIndex->FlowCntSnapshot);
		}
	}

	printf("QueueCnt : %lli\n", s_PacketQueueCnt);	
	printf("DecodeCnt: %lli\n", s_PacketDecodeCnt);	
}

//---------------------------------------------------------------------------------------------

void Flow_Stats(bool IsReset, u32* pFlowCntSnapShot, u64* pFlowCntTotal, float * pCPUUse)
{
	if (pFlowCntSnapShot)	pFlowCntSnapShot[0] = s_FlowCntSnapshotLast;
	if (pFlowCntTotal)		pFlowCntTotal[0]	= s_FlowCntTotal;

	u64 TotalTSC = 0;
	u64 DecodeTSC = 0;
	for (int i=0; i < s_DecodeCPUActive; i++)
	{
		TotalTSC 	+= s_DecodeThreadTSCTop[i];
		DecodeTSC 	+= s_DecodeThreadTSCDecode[i];
	}
	if (IsReset)
	{
		for (int i=0; i < s_DecodeCPUActive; i++)
		{
			s_DecodeThreadTSCTop[i]		= 0;
			s_DecodeThreadTSCDecode[i]	= 0;
		}
	}
	if (pCPUUse) pCPUUse[0] = DecodeTSC * inverse(TotalTSC);
}

/* vim: set ts=4 sts=4 */
