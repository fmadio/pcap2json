//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
// 
// PCAP to JSON file conversion. convers a PCAP and extracts basic IP / TCP / UDP information
// that can be fed into Elastic Search for further processing and analysis 
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

double TSC2Nano = 0;

//---------------------------------------------------------------------------------------------
// pcap headers
/*
#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
#define PCAPHEADER_MAJOR			2
#define PCAPHEADER_MINOR			4
#define PCAPHEADER_LINK_ETHERNET	1
#define PCAPHEADER_LINK_ERF			197	

//-------------------------------------------------------------------------------------------------

typedef struct
{
	u32				Sec;				// time stamp sec since epoch 
	u32				NSec;				// nsec fraction since epoch

	u32				LengthCapture;		// captured length, inc trailing / aligned data
	u32				LengthWire;			// length on the wire

} __attribute__((packed)) PCAPPacket_t;

// per file header

typedef struct
{

	u32				Magic;
	u16				Major;
	u16				Minor;
	u32				TimeZone;
	u32				SigFlag;
	u32				SnapLen;
	u32				Link;

} __attribute__((packed)) PCAPHeader_t;
*/

//---------------------------------------------------------------------------------------------
// tunables

bool			g_Verbose				= false;				// verbose print mode
bool			g_JSON_MAC				= false;				// print MAC address in output

//---------------------------------------------------------------------------------------------

static void help(void)
{
	fprintf(stderr, "fmad engineering all rights reserved\n");
	fprintf(stderr, "http://www.fmad.io\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "pcap2json is a high speed PCAP meta data extraction utility\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "example converting a pcap to json:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "cat /tmp/test.pcap | pcap2json > test.json\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Command Line Arguments:\n");
	fprintf(stderr, " --mac               : include MAC information into the JSON output\n");
	fprintf(stderr, "\n");
}

//---------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	u8* FileInName 		= NULL;
	u8* FileOutName 	= NULL;

	for (int i=0; i < argc; i++)
	{
		if (strcmp(argv[i], "-v") == 0)
		{
			g_Verbose = true;
		}

		// include MAC address
		if (strcmp(argv[i], "--mac") == 0)
		{
			fprintf(stderr, "Including MAC Address\n");
			g_JSON_MAC = true;
		}

		if (strcmp(argv[i], "--help") == 0)
		{
			help();
			return 0;
		}
	}

	CycleCalibration();

	// get the hosts name
	u8 DeviceName[128];
	gethostname(DeviceName, sizeof(DeviceName));	

	FILE* FileIn 	= stdin;
	FILE* FileOut 	= stdout;

	u64  PCAPOffset	= 0;

	// read header
	PCAPHeader_t HeaderMaster;
	int rlen = fread(&HeaderMaster, 1, sizeof(HeaderMaster), FileIn);
	if (rlen != sizeof(HeaderMaster))
	{
		fprintf(stderr, "Failed to read pcap header\n");
		return 0;
	}
	PCAPOffset		= sizeof(PCAPHeader_t);

	u64 TScale = 0;
	switch (HeaderMaster.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: fprintf(stderr, "PCAP Nano\n"); TScale = 1;    break;
	case PCAPHEADER_MAGIC_USEC: fprintf(stderr, "PCAP Micro\n"); TScale = 1000; break;
	}

	u64 LastTS					= 0;
	u64 NextPrintTS				= 0;

	u8* 			Pkt			= malloc(1024*1024);	
	PCAPPacket_t*	PktHeader	= (PCAPPacket_t*)Pkt;

	u64				PrintNextTSC	= 0;
	u64				StartTSC		= rdtsc();
	u64				LastTSC			= rdtsc();
	u64				PCAPOffsetLast	= 0;

	while (!feof(FileIn))
	{
		u64 TSC = rdtsc();

		// progress stats
		if (TSC > PrintNextTSC)
		{
			PrintNextTSC = TSC + ns2tsc(1e9);
			float bps = ((PCAPOffset - PCAPOffsetLast) * 8.0) / (tsc2ns(TSC - LastTSC)/1e9); 

			fprintf(stderr, "%.3f GB   %.6f Gbps\n", (float)PCAPOffset / kGB(1), bps / 1e9);

			LastTSC 		= TSC;
			PCAPOffsetLast 	= PCAPOffset;	
		}

		// header 
		int rlen = fread(PktHeader, 1, sizeof(PCAPPacket_t), FileIn);
		if (rlen != sizeof(PCAPPacket_t)) break;
		PCAPOffset += sizeof(PCAPPacket_t);

		// validate size
		if ((PktHeader->LengthCapture == 0) || (PktHeader->LengthCapture > 128*1024)) 
		{
			fprintf(stderr, "Invalid packet length: %i\n", PktHeader->LengthCapture);
			break;
		}

		// payload
		rlen = fread(PktHeader + 1, 1, PktHeader->LengthCapture, FileIn);
		if (rlen != PktHeader->LengthCapture)
		{
			fprintf(stderr, "payload read fail %i expect %i\n", rlen, PktHeader->LengthCapture);
			break;
		}
		PCAPOffset += PktHeader->LengthCapture; 

		u64 PacketTS = (u64)PktHeader->Sec * 1000000000ULL + (u64)PktHeader->NSec * TScale;

		// pcap meta data
		fprintf(FileOut, "{\"Device\":\"%s\",\"EpochTS\":%lli,\"CaptureSize\":%6i,\"WireSize\":%6i", 
								DeviceName, 
								PacketTS, 
								PktHeader->LengthCapture, 
								PktHeader->LengthWire); 

		// ether header info
		fEther_t* Ether = (fEther_t*)(PktHeader + 1);	
		u8* Payload 	= (u8*)(Ether + 1);
		u16 EtherProto 	= swap16(Ether->Proto);
		if (g_JSON_MAC)
		{
			fprintf(FileOut, ",\"MAC.Src\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"MAC.Dst\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"MAC.Proto\":%06i",
					Ether->Dst[0],
					Ether->Dst[1],
					Ether->Dst[2],
					Ether->Dst[3],
					Ether->Dst[4],
					Ether->Dst[5],

					Ether->Src[0],
					Ether->Src[1],
					Ether->Src[2],
					Ether->Src[3],
					Ether->Src[4],
					Ether->Src[5],

					EtherProto	
			);
		}

		// MPLS decoder	
		if (EtherProto == ETHER_PROTO_MPLS)
		{
			MPLSHeader_t* MPLS = (MPLSHeader_t*)(Payload);

			u32 MPLSDepth = 0;

			// for now only process outer tag
			// assume there is a sane limint on the encapsulation count
			if (!MPLS->BOS)
			{
				MPLS += 1;
				MPLSDepth++;
			}
			if (!MPLS->BOS)
			{
				MPLS += 1;
				MPLSDepth++;
			}
			if (!MPLS->BOS)
			{
				MPLS += 1;
				MPLSDepth++;
			}

			fprintf(FileOut,",\"MPLSLabel\":%4i,\"MPLS.BOS\":%i,\"MPLS.TC\":%i,\"MPLS.L2\":%i,\"MPLS.TTL\":%i,\"MPLSDepth\":%i",
					MPLS_LABEL(MPLS),
					MPLS->BOS,	
					MPLS->TC,
					MPLS->L2,
					MPLS->TTL,
					MPLSDepth
			);

			// update to next header
			if (MPLS->BOS)
			{
				EtherProto = ETHER_PROTO_IPV4;
				Payload = (u8*)(MPLS + 1);
			}
		}

		// ipv4 info
		if (EtherProto == ETHER_PROTO_IPV4)
		{
			IP4Header_t* IP4 = (IP4Header_t*)Payload;
			fprintf(FileOut,",\"IP.Proto\":%4i,\"IP.Src\":\"%i.%i.%i.%i\",\"IP.Dst\":\"%i.%i.%i.%i\"", 
					IP4->Proto,
					IP4->Src.IP[0],
					IP4->Src.IP[1],
					IP4->Src.IP[2],
					IP4->Src.IP[3],

					IP4->Dst.IP[0],
					IP4->Dst.IP[1],
					IP4->Dst.IP[2],
					IP4->Dst.IP[3]
			);

			// IPv4 protocol decoders 
			u32 IPOffset = (IP4->Version & 0x0f)*4; 
			switch (IP4->Proto)
			{
			case IPv4_PROTO_TCP:
			{
				TCPHeader_t* TCP = (TCPHeader_t*)(Payload + IPOffset);

				u16 Flags = swap16(TCP->Flags);

				fprintf(FileOut,",\"TCP.PortSrc\":%i,\"TCP.PortDst\":%i,\"TCP.SeqNo\":%u,\"TCP.AckNo\":%u,\"TCP.FIN\":%i,\"TCP.SYN\":%i,\"TCP.RST\":%i,\"TCP.PSH\":%i,\"TCP.ACK\":%i,\"TCP.Window\":%i",
						swap16(TCP->PortSrc),
						swap16(TCP->PortDst),
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
			break;
			case IPv4_PROTO_UDP:
			{
				UDPHeader_t* UDP = (UDPHeader_t*)(Payload + IPOffset);

				fprintf(FileOut,",\"UDP.PortSrc\":%i,\"UDP.PortDst\":%i",
						swap16(UDP->PortSrc),
						swap16(UDP->PortDst)
				);
			}
			break;
			}
		}
		fprintf(FileOut, "}\n");
	}
}

/* vim: set ts=4 sts=4 */
