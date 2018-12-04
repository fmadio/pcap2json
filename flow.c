//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
// 
// guts of the flow calcuation. generats a SHA1 of the MAC/IP/Proto/Port
// and maps packets into this
//
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

static u64				s_FlowCntTotal		= 0;				// total number of active flows
static u64				s_FlowCntSnapshot	= 0;				// number of flows in this snapshot
static u32				s_FlowCntSnapshotLast = 0;				// last total flows in the last snapshot

static u64				s_FlowMax			= 4*1024*1024;		// maximum number of flows 
static FlowRecord_t*	s_FlowList			= NULL;				// list of statically allocated flows
static FlowRecord_t**	s_FlowHash			= NULL;				// flash hash index

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

static FlowRecord_t* FlowAlloc(FlowRecord_t* F)
{
	assert(s_FlowCntSnapshot < s_FlowMax);

	FlowRecord_t* Flow = &s_FlowList[ s_FlowCntSnapshot++ ]; 
	memset(Flow, 0, sizeof(FlowRecord_t) );

	// copy flow values, leaving the counters reset at zero 
	memcpy(Flow, F, offsetof(FlowRecord_t, pad));

	// copy per packet state
	Flow->TCPLength = F->TCPLength;

	return Flow;
}

//---------------------------------------------------------------------------------------------

static void FlowInsert(FlowRecord_t* FlowPkt, u32* SHA1, u32 Length, u64 TS)
{
	u32 Index = HashIndex(SHA1);

	FlowRecord_t* F = NULL;

	bool IsFlowNew = false;

	// first record ?
	if (s_FlowHash[ Index ] == NULL)
	{
		F = FlowAlloc(FlowPkt);

		F->SHA1[0] = SHA1[0];
		F->SHA1[1] = SHA1[1];
		F->SHA1[2] = SHA1[2];
		F->SHA1[3] = SHA1[3];
		F->SHA1[4] = SHA1[4];

		F->Next		= NULL;
		F->Prev		= NULL;

		s_FlowHash[Index] = F;

		IsFlowNew = true;
	}
	else
	{
		F = s_FlowHash[ Index ];

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
			F = FlowAlloc(FlowPkt);

			F->SHA1[0] = SHA1[0];
			F->SHA1[1] = SHA1[1];
			F->SHA1[2] = SHA1[2];
			F->SHA1[3] = SHA1[3];
			F->SHA1[4] = SHA1[4];

			F->Next		= NULL;
			F->Prev		= NULL;

			FPrev->Next = F;
			F->Prev		= FPrev;

			IsFlowNew = true;
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
static u32 FlowDump(struct Output_t* Out, u64 TS, FlowRecord_t* Flow) 
{
	u8 OutputStr[1024];
	u8* Output 		= OutputStr;
	u8* OutputStart = Output;

	fProfile_Start(1, "FlowDump");

	// ES header for bulk upload
	Output += sprintf(Output, "{\"index\":{\"_index\":\"%s\",\"_type\":\"flow_record\",\"_score\":null}}\n", g_CaptureName);

	// actual payload
	Output += sprintf(Output, "{\"timestamp\":%f,\"TS\":\"%s\",\"FlowCnt\":%lli,\"Device\":\"%s\"", TS/1e6, FormatTS(TS), s_FlowCntSnapshot, g_DeviceName);

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

	fProfile_Stop(1);
}

//---------------------------------------------------------------------------------------------
// clear out the flow records 
static void FlowReset(void)
{
	fProfile_Start(7, "FlowReset");

	memset(s_FlowHash, 0, sizeof(FlowRecord_t*) * (2 << 20) );

	// save last count for stats
	s_FlowCntSnapshotLast = s_FlowCntSnapshot;

	s_FlowCntSnapshot = 0;

	fProfile_Stop(7);
}

//---------------------------------------------------------------------------------------------
//
// parse a packet and generate a flow record 
//
void Flow_DecodePacket(struct Output_t* Out, u64 PacketTS, PCAPPacket_t* PktHeader)
{

	fProfile_Start(2, "DecodePacket");

	FlowRecord_t	sFlow;	
	FlowRecord_t*	Flow = &sFlow;	
	memset(Flow, 0, sizeof(FlowRecord_t));

	// assume single packet flow
	Flow->TotalPkt	 	= 1;
	Flow->TotalByte 	= PktHeader->LengthWire;

	// ether header info
	fEther_t* Ether = (fEther_t*)(PktHeader + 1);	
	u8* Payload 	= (u8*)(Ether + 1);
	u16 EtherProto 	= swap16(Ether->Proto);

	Flow->EtherProto	= EtherProto;
	Flow->EtherSrc[0]	= Ether->Src[0];
	Flow->EtherSrc[1]	= Ether->Src[1];
	Flow->EtherSrc[2]	= Ether->Src[2];
	Flow->EtherSrc[3]	= Ether->Src[3];
	Flow->EtherSrc[4]	= Ether->Src[4];
	Flow->EtherSrc[5]	= Ether->Src[5];

	Flow->EtherDst[0]	= Ether->Dst[0];
	Flow->EtherDst[1]	= Ether->Dst[1];
	Flow->EtherDst[2]	= Ether->Dst[2];
	Flow->EtherDst[3]	= Ether->Dst[3];
	Flow->EtherDst[4]	= Ether->Dst[4];
	Flow->EtherDst[5]	= Ether->Dst[5];
	
	// VLAN decoder
	if (EtherProto == ETHER_PROTO_VLAN)
	{
		VLANTag_t* Header 	= (VLANTag_t*)(Ether+1);
		u16* Proto 			= (u16*)(Header + 1);

		// update to the acutal proto / ipv4 header
		EtherProto 			= swap16(Proto[0]);
		Payload 			= (u8*)(Proto + 1);

		// first vlan tag
		Flow->VLAN[0]		= VLANTag_ID(Header);

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
			Flow->VLAN[1]		= VLANTag_ID(Header);
		}
	}

	// MPLS decoder	
	if (EtherProto == ETHER_PROTO_MPLS)
	{
		MPLSHeader_t* MPLS = (MPLSHeader_t*)(Payload);

		u32 MPLSDepth = 0;

		// first MPLS 
		Flow->MPLS[0]		= MPLS_LABEL(MPLS);
		Flow->MPLStc[0]		= MPLS->TC;

		// for now only process outer tag
		// assume there is a sane limint on the encapsulation count
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// seccond 
			Flow->MPLS[1]		= MPLS_LABEL(MPLS);
			Flow->MPLStc[1]		= MPLS->TC;
		}
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// third 
			Flow->MPLS[2]		= MPLS_LABEL(MPLS);
			Flow->MPLStc[2]		= MPLS->TC;
		}
		if (!MPLS->BOS)
		{
			MPLS += 1;
			MPLSDepth++;

			// fourth 
			Flow->MPLS[3]		= MPLS_LABEL(MPLS);
			Flow->MPLStc[3]		= MPLS->TC;
		}

		// update to next header
		if (MPLS->BOS)
		{
			EtherProto = ETHER_PROTO_IPV4;
			Payload = (u8*)(MPLS + 1);
		}
	}

	// update final ethernet protocol
	Flow->EtherProto	= EtherProto;

	// ipv4 info
	if (EtherProto == ETHER_PROTO_IPV4)
	{
		IP4Header_t* IP4 = (IP4Header_t*)Payload;

		Flow->IPSrc[0] = IP4->Src.IP[0];	
		Flow->IPSrc[1] = IP4->Src.IP[1];	
		Flow->IPSrc[2] = IP4->Src.IP[2];	
		Flow->IPSrc[3] = IP4->Src.IP[3];	

		Flow->IPDst[0] = IP4->Dst.IP[0];	
		Flow->IPDst[1] = IP4->Dst.IP[1];	
		Flow->IPDst[2] = IP4->Dst.IP[2];	
		Flow->IPDst[3] = IP4->Dst.IP[3];	

		Flow->IPProto = IP4->Proto;

		// IPv4 protocol decoders 
		u32 IPOffset = (IP4->Version & 0x0f)*4; 
		switch (IP4->Proto)
		{
		case IPv4_PROTO_TCP:
		{
			TCPHeader_t* TCP = (TCPHeader_t*)(Payload + IPOffset);

			Flow->PortSrc	= swap16(TCP->PortSrc);
			Flow->PortDst	= swap16(TCP->PortDst);

			// make a copy of the tcp header 
			Flow->TCPHeader = TCP[0];

			// payload length
			u32 TCPOffset = ((TCP->Flags&0xf0)>>4)*4;
			Flow->TCPLength =  swap16(IP4->Len) - IPOffset - TCPOffset;

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
						Flow->TCPWindowScale = Options[2];
						break;

					// SACK
					case 0x5:
						Flow->TCPIsSACK = true;
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

			Flow->PortSrc	= swap16(UDP->PortSrc);
			Flow->PortDst	= swap16(UDP->PortDst);
		}
		break;
		}
	}
	fProfile_Stop(2);

	// generate SHA1
	// nice way to grab all packets for a single flow, search for the sha1 hash	
	// NOTE: FlowRecord_t setup so the first 64B contains only the flow info
	//       with packet and housekeeping info stored after. sha1_compress
	//       runs on the first 64B only 
	fProfile_Start(3, "SHA");

	u32 SHA1State[5] = { 0, 0, 0, 0, 0 };
	sha1_compress(SHA1State, (u8*)Flow);

	Flow->SHA1[0] = SHA1State[0];
	Flow->SHA1[1] = SHA1State[1];
	Flow->SHA1[2] = SHA1State[2];
	Flow->SHA1[3] = SHA1State[3];
	Flow->SHA1[4] = SHA1State[4];
	
	fProfile_Stop(3);

	// packet mode then print record as a packet 
	if (g_IsJSONPacket)
	{
		FlowDump(Out, PacketTS, Flow);
	}

	// update the flow records
	if (g_IsJSONFlow)
	{
		fProfile_Start(4, "FlowInsert");

		// insert to flow table
		FlowInsert(Flow, SHA1State, PktHeader->LengthWire, PacketTS);

		fProfile_Stop(4);

		// purge the flow records every 100msec
		static u64 LastPacketTS = 0;
		s64 dTS = PacketTS - LastPacketTS;
		if (dTS > g_FlowSampleRate)
		{
			LastPacketTS = PacketTS;

			fProfile_Start(5, "FlowDump");

			for (int i=0; i < s_FlowCntSnapshot; i++)
			{
				FlowRecord_t* Flow = &s_FlowList[i];	
				FlowDump(Out, PacketTS, Flow);
			}

			// reset index and counts
			FlowReset();

			fProfile_Stop(5);
		}
	}
}

//---------------------------------------------------------------------------------------------
// allocate memory and house keeping
void Flow_Open(void)
{

	// allocate and clear flow index
	s_FlowHash = (FlowRecord_t **)malloc( sizeof(FlowRecord_t *) * (2 << 20) );
	assert(s_FlowHash != NULL);

	// allocate statically allocated flow list
	s_FlowList = (FlowRecord_t *)malloc (sizeof(FlowRecord_t) * s_FlowMax );
	assert(s_FlowList != NULL);

	// reset flow info
	FlowReset();
}

//---------------------------------------------------------------------------------------------
// shutdown / flush
void Flow_Close(struct Output_t* Out, u64 LastTS)
{
	// output last flow data
	if (g_IsJSONFlow)
	{
		for (int i=0; i < s_FlowCntSnapshot; i++)
		{
			FlowRecord_t* Flow = &s_FlowList[i];	
			FlowDump(Out, LastTS, Flow);
		}
		printf("Total Flows: %i\n", s_FlowCntSnapshot);
	}
}

//---------------------------------------------------------------------------------------------

void Flow_Stats(u32* pFlowCntSnapShot)
{
	pFlowCntSnapShot[0] = s_FlowCntSnapshotLast;
}

/* vim: set ts=4 sts=4 */
