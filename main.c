//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015-2019, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
// 
// pcap flow exporter 
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
#include "fFile.h"
#include "tcpstream.h"
#include "udpstream.h"

//---------------------------------------------------------------------------------------------

typedef struct
{
	char* Path;				// path to the file
	char	Name[128];		// short name
	FILE*	F;				// bufferd io file handle
	int		fd;				// file handler of the mmap attached data
	u64		Length;			// exact file length
	u64		MapLength;		// 4KB aligned mmap length
	u8*		Map;			// raw mmap ptr

	u64		ReadPos;		// current read pointer
	u64		PktCnt;			// number of packets processed

	u8*		PacketBuffer;	// temp read buffer
	bool	Finished;		// read completed

	u64		TS;				// last TS processed

} PCAPFile_t;

#define FLOW_TYPE_TCP		1	
#define FLOW_TYPE_UDP		2	

typedef struct
{
	u64		Data[64/8];			// protocol specific unique hash

	u32		Hash;				// copy of the flow hash
	u32		Type;				// what kind of flow is this

	u64		PktCnt;				// number of packets in this flow
	u64		Bytes;				// number of bytes in this flow
	u64		TSFirst;			// first packet of the flow
	u64		TSLast;				// last packet of the flow 
			
								// for duplex matching
	u32		TCPSeqNo;			// tcp syn/synack seq no

	u32		Next;				// next flow has index for this hash

} FlowHash_t;

// specific protocol hash info

typedef struct
{
	u8		MACSrc[6];
	u8		MACDst[6];
	IP4_t	IPSrc;
	IP4_t	IPDst;

	u16		PortSrc;
	u16		PortDst;

	u16		DeviceID;			// packet broker device ID 
	u16		DevicePort;			// packet broker device port 

} __attribute__((packed)) TCPHash_t;

typedef struct
{
	u8		MACSrc[6];
	u8		MACDst[6];
	IP4_t	IPSrc;
	IP4_t	IPDst;

	u16		PortSrc;
	u16		PortDst;

	u16		DeviceID;			// packet broker device ID 
	u16		DevicePort;			// packet broker device port 

} UDPHash_t;

double TSC2Nano = 0;

//---------------------------------------------------------------------------------------------
// tunables
static u64		s_MaxPackets			= (1ULL<<63);			// max number of packets to process
static s64		s_TimeZoneOffset		= 0;					// local timezone
u64				g_TotalMemory			= 0;					// total memory consumption
u64				g_TotalMemoryTCP		= 0;					// total memory of keeping out of order tcp packets 
bool			g_Verbose				= false;				// verbose print mode

//---------------------------------------------------------------------------------------------
// first level index 

static u32*					s_FlowIndex;						// 24b index into first level list 
static u64					s_FlowIndexBits = 24;				// bit depth of the hash index, default to 24b / 64MB
static u64					s_FlowIndexMask;					// bit mask for for the hash depth 
static u32					s_FlowIndexDepthMax;				// current max depth of an index 
static u64					s_FlowIndexDepthS0;					// calculate mean depth 
static u64					s_FlowIndexDepthS1;					// calculate mean depth 

static FlowHash_t*			s_FlowList;							// statically allocated max number of flows 
static u32					s_FlowListPos = 1;					// current allocated flow
static u32					s_FlowListMax;						// max number of flows

static u64					s_FlowListPacketMin 	= 0;		// minimum number of packets to show entry for

static u8*					s_FlowExtract 			= NULL;		// boolean to extract the specified flow id
static bool					s_FlowExtractEnable 	= false;	// indicaes flow extraction 

static u32					s_ExtractTCPEnable 		= false;	// request extraction of tcp stream
static u8*					s_ExtractTCPFlow		= NULL;		// boolean to extract the specified flow id

static bool					s_ExtractTCPPortEnable 	= false;	// extract all tcp flows with the specified port number
static u32					s_ExtractTCPPortMin		= 0;
static u32					s_ExtractTCPPortMax		= 0;
static struct TCPStream_t** s_ExtractTCP			= NULL; 	// list of tcp stream extraction objects 

static u32					s_DisableTCPPortCnt 	= 0;		// extract all tcp flows with the specified port number
static u32					s_DisableTCPPortCntMax 	= 32;		// max list of port ranges 
static u32					s_DisableTCPPortMin[32];
static u32					s_DisableTCPPortMax[32];

static bool					s_ExtractUDPPortEnable 	= false;	// extract all UDP flows within the specified port range 
static u32					s_ExtractUDPPortMin		= 0;
static u32					s_ExtractUDPPortMax		= 0;
static struct UDPStream_t**	s_ExtractUDP			= NULL;

static u32					s_DisableUDPPortCnt 	= 0;		// extract all tcp flows with the specified port number
static u32					s_DisableUDPPortCntMax 	= 32;		// max list of port ranges 
static u32					s_DisableUDPPortMin[32];
static u32					s_DisableUDPPortMax[32];

static bool					s_ExtractIPEnable		= false;	// extract an IP range into a seperate pcap file
static u32					s_ExtractIPMask			= 0;		// /32 mask
static u32					s_ExtractIPMatch		= 0;		// match 

static bool					s_ExtractPortEnable		= false;	// extract TCP/UDP port range to a seperate pcap file 
static u32					s_ExtractPortMin		= 0;		// min port range 
static u32					s_ExtractPortMax		= 0;		// max port range 

static bool					s_EnableFlowDisplay 	= true;		// print full flow information
bool						g_EnableTCPHeader 		= false;	// output packet header in tcp stream
bool						g_EnableUDPHeader 		= false;	// output packet header in udp stream

static bool					s_EnableFlowLog			= true;		// write flow log in realtime
static char					s_FlowLogPath[128];					// where to store the flow log
static FILE*				s_FlowLogFile			= NULL;		// file handle where to write flows

static u64					s_PCAPTimeScale			= 1;		// timescale all raw pcap time stamps

bool						g_EnableMetamako		= false;	// enable metamako timestamp decoding 

//---------------------------------------------------------------------------------------------

void sha1_compress(uint32_t state[static 5], const uint8_t block[static 64]);

//---------------------------------------------------------------------------------------------
// mmaps a pcap file in full
static PCAPFile_t* OpenPCAP(char* Path, bool EnableStdin)
{
	PCAPFile_t* F = (PCAPFile_t*)malloc( sizeof(PCAPFile_t) );
	assert(F != NULL);
	memset(F, 0, sizeof(PCAPFile_t));
	F->Path		= Path;

	if (!EnableStdin)
	{
		F->F = fopen(Path, "r");
		if (F->F == NULL)
		{
			fprintf(stderr, "failed to open buffered file [%s]\n", Path);
			return NULL;
		}

		struct stat fstat;	
		if (stat(Path, &fstat) < 0)
		{
			fprintf(stderr, "failed to get file size [%s]\n", Path);
			return NULL;
		}
		F->Length 	= fstat.st_size;
	}
	else
	{
		F->F 		= stdin;
		F->Length 	= 1e15;		// 1PB limit
	}

	// note always map as read-only 
	PCAPHeader_t Header1;
	PCAPHeader_t* Header = NULL; 
	{
		int ret = fread(&Header1, 1, sizeof(Header1), F->F);
		if (ret != sizeof(PCAPHeader_t))
		{
			fprintf(stderr, "failed to read header %i\n", ret);
			return NULL;
		}

		Header = &Header1;
		F->PacketBuffer	= malloc(32*1024);
		assert(F->PacketBuffer != NULL);
	}

	switch (Header->Magic)
	{
	case PCAPHEADER_MAGIC_USEC: fprintf(stderr, "USec PACP\n"); s_PCAPTimeScale = 1000; break;
	case PCAPHEADER_MAGIC_NANO: fprintf(stderr, "Nano PACP\n"); s_PCAPTimeScale = 1; break;
	default:
		fprintf(stderr, "invalid pcap header %08x\n", Header->Magic);
		return NULL;
	}
	F->ReadPos +=  sizeof(PCAPHeader_t);

	return F;
}

//---------------------------------------------------------------------------------------------
// get the next packet
static PCAPPacket_t* ReadPCAP(PCAPFile_t* PCAP)
{
	int ret;
	PCAPPacket_t* Pkt = (PCAPPacket_t*)PCAP->PacketBuffer;
	ret = fread(Pkt, 1, sizeof(PCAPPacket_t), PCAP->F);
	if (ret != sizeof(PCAPPacket_t))
	{
		fprintf(stderr, "header read failed. expect:%li got:%i errno:%i %s\n", sizeof(PCAPPacket_t), ret, errno, strerror(errno));
		fprintf(stderr, "errno: %i\n", ferror(PCAP->F));
		return NULL;
	}

	if (PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture > PCAP->Length)
	{
		fprintf(stderr, "read overflow %lli %li %i > %lli\n", 
				PCAP->ReadPos,
				sizeof(PCAPPacket_t),
				Pkt->LengthCapture,
				PCAP->Length
		);	
		return NULL; 
	}

	ret = fread(Pkt+1, 1, Pkt->LengthCapture, PCAP->F);
	if (ret != Pkt->LengthCapture)
	{
		fprintf(stderr, "payload read failed. expect:%li got:%i errno:%i %s\n", sizeof(PCAPPacket_t), ret, errno, strerror(errno));
		fprintf(stderr, "errno: %i\n", ferror(PCAP->F));
		return NULL;
	}

	PCAP->ReadPos += Pkt->LengthCapture;
	return Pkt;
}

//---------------------------------------------------------------------------------------------
// helpers for network formating 
static u64 PCAPTimeStamp(PCAPPacket_t* Pkt)
{
	return s_TimeZoneOffset + Pkt->Sec * k1E9 + Pkt->NSec * s_PCAPTimeScale;
}
static fEther_t * PCAPETHHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	
	return E;
}

static IP4Header_t* PCAPIP4Header(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	return IP4;
}

static TCPHeader_t* PCAPTCPHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);
	u32 TCPOffset = ((TCP->Flags&0xf0)>>4)*4;

	return TCP;
}

static u8* PCAPTCPPayload(PCAPPacket_t* Pkt, u32* Length)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);
	u32 TCPOffset = ((TCP->Flags&0xf0)>>4)*4;

	Length[0] = swap16(IP4->Len) - IPOffset - TCPOffset;

	return (u8*)TCP + TCPOffset;
}

static UDPHeader_t* PCAPUDPHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	UDPHeader_t* UDP = (UDPHeader_t*)( ((u8*)IP4) + IPOffset);

	return UDP;
}

static Metamako_t* PCAPMetamako(PCAPPacket_t* Pkt)
{
	u8* Payload = (u8*)(Pkt+1);	

	s32 Offset = Pkt->LengthCapture;
	Offset -= sizeof(Metamako_t); 

	// required if pcap has no FCS
	Offset += 4; 

	if (Offset < 0)
	{
		printf("pkt length %i %i\n", Pkt->Length, Pkt->LengthCapture);
	}

 	assert(Offset > 0);	

	Metamako_t* M = (Metamako_t*)(Payload + Offset); 

	return M;
}

//---------------------------------------------------------------------------------------------

static void PrintMAC(FILE* Out, u8* MAC)
{
	fprintf(Out, "%02x:%02x:%02x:%02x:%02x:%02x",
			MAC[0],
			MAC[1],
			MAC[2],
			MAC[3],
			MAC[4],
			MAC[5]
		  );
}

static void PrintIP4(FILE* Out, IP4_t IP)
{
	fprintf(Out, "%3i.%3i.%3i.%3i", IP.IP[0], IP.IP[1], IP.IP[2], IP.IP[3]); 
}

//---------------------------------------------------------------------------------------------

static void PrintFlowTCP(FILE* Out, FlowHash_t* F, u32 FlowID, u32 FlowCnt)
{
	TCPHash_t* TCP = (TCPHash_t*)F->Data;
	fprintf(Out, "%5i FlowID: %8i | TCP  ", FlowCnt, FlowID); 	
	PrintMAC(Out, TCP->MACSrc);
	fprintf(Out, " -> ");
	PrintMAC(Out, TCP->MACDst);

	fprintf(Out, " | ");
	PrintIP4(Out, TCP->IPSrc);
	fprintf(Out, " -> ");
	PrintIP4(Out, TCP->IPDst);

	fprintf(Out, " | %6i -> %6i ", TCP->PortSrc, TCP->PortDst);

	fprintf(Out, " | ");
	fprintf(Out, " %'16lld Pkts ", F->PktCnt);
	fprintf(Out, " %'16lli Bytes ", F->Bytes);

	fprintf(Out, " | ");
	fprintf(Out, " %s -> %s", FormatTS(F->TSFirst), FormatTS(F->TSLast) ); 
	fprintf(Out, " : %s", FormatTS(F->TSLast - F->TSFirst));

	fprintf(Out, " | ");
	fprintf(Out, " Seq:%08x", F->TCPSeqNo);

	fprintf(Out, "\n");
}

//---------------------------------------------------------------------------------------------

static void PrintFlowUDP(FILE* Out, FlowHash_t* F, u32 FlowID, u32 FlowCnt)
{

	UDPHash_t* UDP = (UDPHash_t*)F->Data;
	fprintf(Out, "%5i FlowID: %8i | UDP  ", FlowCnt, FlowID); 	
	PrintMAC(Out, UDP->MACSrc);
	fprintf(Out, " -> ");
	PrintMAC(Out, UDP->MACDst);

	fprintf(Out, " | ");
	PrintIP4(Out, UDP->IPSrc);
	fprintf(Out, " -> ");
	PrintIP4(Out, UDP->IPDst);

	fprintf(Out, " | %6i -> %6i ", UDP->PortSrc, UDP->PortDst);

	fprintf(Out, " | ");
	fprintf(Out, " %'16lld Pkts ", F->PktCnt);
	fprintf(Out, " %'16lli Bytes ", F->Bytes);

	fprintf(Out, " | ");
	fprintf(Out, " %s -> %s", FormatTS(F->TSFirst), FormatTS(F->TSLast) ); 
	fprintf(Out, " : %s", FormatTS(F->TSLast - F->TSFirst));

	fprintf(Out, "\n");
}

//---------------------------------------------------------------------------------------------

static u32 FlowHash(u32 Type, u8* Payload, u32 Length)
{
	// generate SHA1
	u32 SHA1State[5] = { 0, 0, 0, 0, 0 };

	// hash the first 64B
	sha1_compress(SHA1State, (u8*)Payload);

	u8* Data8 = (u8*)SHA1State;

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

	/*
	// DEK packets usually have enough entropy for this to be enough 
	u32 Hash = Type; 
	for (int i=0; i < Length; i++)
	{
		Hash = ((Hash << 5ULL) ^ (Hash >> (32-5))) ^ (u64)Payload[i];
	}
	*/

	// reduce to a 32b hash
	return Hash;
}

//---------------------------------------------------------------------------------------------

static u32 FlowAdd(FlowHash_t* Flow, u32 PktLength, u64 TS) 
{
	if (s_FlowListPos >= s_FlowListMax) return 0;

	FlowHash_t* F 	= NULL; 

	// first level has is 24b index, followed by list of leaf nodes
	Flow->Hash 		= FlowHash(Flow->Type, (u8*)Flow->Data, 64);
	u32 Index 		= Flow->Hash & s_FlowIndexMask;

	u32 FlowIndex 	= 0;
	bool IsFlowNew 	= false;

	u32 HashDepth	= 0;

	if (s_FlowIndex[Index] != 0)
	{
		F = s_FlowList +  s_FlowIndex[Index];
		bool Found = false;
		for (int t=0; t < 1e6; t++)
		{
			HashDepth++;

			// flow matched
			if (memcmp(F->Data, Flow->Data, 64) == 0)
			{
				Found = true;
				break;
			}

			if (F->Next == 0) break;
			F = s_FlowList + F->Next;
			assert(t < 99e3);
		}

		// keep stats on the max depth
		if (s_FlowIndexDepthMax  < HashDepth)
		{
			fprintf(stderr, "Hash New Max Depth: %i : %08x : ", HashDepth, Flow->Hash); 
			for (int i=0; i < 64/8; i++) fprintf(stderr, "%016llx ", Flow->Data[i]);
			fprintf(stderr, "\n");

			s_FlowIndexDepthMax = HashDepth;
		}
		s_FlowIndexDepthS0	+= 1; 
		s_FlowIndexDepthS1	+= HashDepth; 

		// new flow
		if (Found)
		{
		}
		else
		{
			F = &s_FlowList[ s_FlowListPos++ ];
			assert(s_FlowListPos < s_FlowListMax);

			memcpy(F, Flow, sizeof(FlowHash_t));
			F->Next = s_FlowIndex[Index];

			s_FlowIndex[Index] = F - s_FlowList;

			IsFlowNew = true; 
		}
	}
	else
	{
		F = &s_FlowList[ s_FlowListPos++ ];
		assert(s_FlowListPos < s_FlowListMax);

		memcpy(F, Flow, sizeof(FlowHash_t));
		F->Next = 0;

		s_FlowIndex[Index] = F - s_FlowList; 
		IsFlowNew = true; 
	}

	// update stats

	F->PktCnt++;
	F->Bytes += PktLength;
	F->TSFirst	= IsFlowNew ? TS : F->TSFirst;
	F->TSLast	= TS;

	// update flow log
	if (IsFlowNew && s_EnableFlowLog)
	{
		u32 ID = F - s_FlowList;
		switch (F->Type)
		{
		case FLOW_TYPE_TCP: PrintFlowTCP(s_FlowLogFile, F, ID, s_FlowListPos); break;
		case FLOW_TYPE_UDP: PrintFlowUDP(s_FlowLogFile, F, ID, s_FlowListPos); break;
		}
	}
	return F - s_FlowList;
}

//---------------------------------------------------------------------------------------------

static void PrintHumanFlows(void)
{
	u64 PktMax = 0;
	/*
	for (int i=1; i < s_FlowListPos; i++)
	{
		FlowHash_t* F = &s_FlowList[i];
		if (PktMax < F->PktCnt) PktMax = F->PktCnt;
	}
	*/

	u32 FlowCnt = 0;
	s32 Remain = s_FlowListPos-1;
	while (Remain > 0)
	{
		u64 NextMax = 1e16;
		for (int i=1; i < s_FlowListPos; i++)
		{
			FlowHash_t* F = &s_FlowList[i];
			if (F->PktCnt == PktMax)
			{
				if (F->PktCnt >= s_FlowListPacketMin)
				{
					switch (F->Type)
					{
					case FLOW_TYPE_TCP: PrintFlowTCP(stdout, F, i, FlowCnt); break;
					case FLOW_TYPE_UDP: PrintFlowUDP(stdout, F, i, FlowCnt); break;
					}
				}
				
				Remain--;
				FlowCnt++;
				assert(Remain >= 0);
			}
			else if (F->PktCnt > PktMax)
			{
				if (NextMax > F->PktCnt) NextMax = F->PktCnt;
			}
		}

		//printf("%i -> %i : %i\n", PktMax, NextMax, Remain);
		PktMax = NextMax;
	}
}

//---------------------------------------------------------------------------------------------

static void print_usage(void)
{
	fprintf(stderr, "pcap_flows: <pcap>>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Version: %s %s\n", __DATE__, __TIME__);
	fprintf(stderr, "Contact: support at fmad.io\n"); 
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  --output-tcp <filename>                  | write TCP output to the specified file name\n");
	fprintf(stderr, "  --output-udp <filename>                  | write UDP output to the specified file name\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  --packet-max  <number>                   | only process the first <number> packets\n");
	fprintf(stderr, "  --flow-max  <number>                     | sets max flow count to <number> packets\n");
	fprintf(stderr, "  --flow-hash-bits  <number>               | sets number of bits to use for the flow hash index\n");
	fprintf(stderr, "  --extract <number>                       | extract FlowID <number> into the output PCAP file\n");
	fprintf(stderr, "  --extract-port <min port>  <max port>    | extract ports between min/max\n");
	fprintf(stderr, "  --extract-ip <address/netmask>           | extract only a subnet\n");
	fprintf(stderr, "  --extract-tcp <number>                   | extract FlowID <number> as a TCP stream to the output file name\n"); 
	fprintf(stderr, "  --extract-tcp-port <min port> <max port> | extract all TCP flows with the specified port in src or dest\n");
	fprintf(stderr, "  --extract-tcp-all                        | extract all TCP flows\n");
	fprintf(stderr, "  --disable-tcp-port <min port> <max port> | do not extract TCP ports within this range\n");
	fprintf(stderr, "  --stdin                                  | read pcap from stdin. e.g. zcat capture.pcap | pcap_flow --stdin\n"); 
	fprintf(stderr, "  --flow-packet-min <number>               | minimum packet count to display flow info\n"); 
	fprintf(stderr, "  --disable-display                        | do not display flow information to stdout\n");
	fprintf(stderr, "  --cpu <number>                           | pin thread to a specific CPU\n"); 
	fprintf(stderr, "  --flow-size-min <bytes>                  | minium file size to flow creation\n"); 
	fprintf(stderr, "  --metamako                               | decode metamako footer\n"); 
	fprintf(stderr, "  --tcpheader                              | include TCP header in output\n"); 
	fprintf(stderr, "  --udpheader                              | include UDP header in output\n"); 
	fprintf(stderr, "\n");
}

//---------------------------------------------------------------------------------------------
static void FlowAlloc(u32 FlowMax)
{
	s_FlowListMax 		= FlowMax;

	if (s_FlowExtract)		free(s_FlowExtract);
	if (s_ExtractTCPFlow)	free(s_ExtractTCPFlow);
	if (s_ExtractTCP) 		free(s_ExtractTCP);
	if (s_ExtractUDP) 		free(s_ExtractUDP);

	s_FlowExtract 		= (u8*)malloc( s_FlowListMax * sizeof(u8) );
	s_ExtractTCPFlow 	= (u8*)malloc( s_FlowListMax * sizeof(u8) );
	s_ExtractTCP	 	= (struct TCPStream_t**)malloc( s_FlowListMax * sizeof(void*) );
	s_ExtractUDP	 	= (struct UDPStream_t**)malloc( s_FlowListMax * sizeof(void*) );

	memset(s_FlowExtract,		0, s_FlowListMax * sizeof(u8) );
	memset(s_ExtractTCPFlow,	0, s_FlowListMax * sizeof(u8) );
	memset(s_ExtractTCP, 		0, s_FlowListMax * sizeof(void*) );
	memset(s_ExtractUDP, 		0, s_FlowListMax * sizeof(void*) );
}

//---------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	int 	FileNameListPos = 0;
	char 	FileNameList[16][256];
	int		FileStdin = false;

	char* 	UDPOutputFileName = NULL;
	char* 	TCPOutputFileName = NULL;

	// allocate flow lists
	FlowAlloc(100e3);							// default flow count

	for (int i=1; i < argc; i++)
	{
		fprintf(stderr, "[%s]\n", argv[i]);
		if (argv[i][0] != '-')
		{
			strcpy(FileNameList[FileNameListPos], argv[i]);
			FileNameListPos++;
		}
		else
		{
			if (strcmp(argv[i], "--packet-max") == 0)
			{
				s_MaxPackets = atoll(argv[i+1]); 
				i+= 1;
				fprintf(stderr, "    setting maximum number of packets to %lli\n", s_MaxPackets);
			}
			// set the maximum number of flows
			else if (strcmp(argv[i], "--flow-max") == 0)
			{
				u32 FlowMax = (u32)atof(argv[i+1]); 
				i++;
				fprintf(stderr, "    set max flow count to %i\n", FlowMax);
				FlowAlloc(FlowMax);							// default flow count
			}
			// set the number of bits for the hash index 
			else if (strcmp(argv[i], "--flow-hash-bits") == 0)
			{
				u32 HashBits = (u32)atoi(argv[i+1]); 
				i++;
				fprintf(stderr, "    set Hash Bit Depth to %i\n", HashBits);
				s_FlowIndexBits = HashBits;
			}

			else if (strcmp(argv[i], "--extract") == 0)
			{
				u32 FlowID = atoi(argv[i+1]); 
				if (FlowID >= sizeof(s_FlowExtract))
				{
					fprintf(stderr, "    flow overflow\n");
					return 0;
				}
				s_FlowExtract[ FlowID ] = 1<<7;
				s_FlowExtractEnable 	= true;
				i++;
			}
			// extract the specified ip range into a seperate pcap 
			else if (strcmp(argv[i], "--extract-ip") == 0)
			{
				// in the form of 192.168.1.1/255.255.255.255
				char* IPRange 		= argv[i+1];
				i++;

				u8 Segment[8][256];
				u32 SegmentPos = 0;
				u32 SegmentLen = 0;
				for (int p=0; p < strlen(IPRange); p++)
				{
					u8 c = IPRange[p];
					if ((c == '.') || (c == '/'))
					{
						Segment[SegmentPos][SegmentLen] = 0;
						//printf("seg len: %i %i : %s\n", SegmentPos, SegmentLen, Segment[SegmentPos]);

						SegmentPos++;
						SegmentLen = 0;
					}
					else
					{
						Segment[SegmentPos][SegmentLen] = c;
						SegmentLen++;
					}
				}

				u32 IP[4];
				u32 Mask[4];

				IP[0] = atoi(Segment[0]);
				IP[1] = atoi(Segment[1]);
				IP[2] = atoi(Segment[2]);
				IP[3] = atoi(Segment[3]);

				Mask[0] = atoi(Segment[4]);
				Mask[1] = atoi(Segment[5]);
				Mask[2] = atoi(Segment[6]);
				Mask[3] = atoi(Segment[7]);

				fprintf(stderr, "    extract ip range %i.%i.%i.%i/%i.%i.%i.%i\n", 
						IP[0],
						IP[1],
						IP[2],
						IP[3],

						Mask[0],
						Mask[1],
						Mask[2],
						Mask[3]);

				s_ExtractIPEnable 	= true;
				s_ExtractIPMatch	= (IP[0] << 0) | (IP[1] << 8) | (IP[2] << 16) | (IP[3] << 24);
				s_ExtractIPMask		= (Mask[0] << 0) | (Mask[1] << 8) | (Mask[2] << 16) | (Mask[3] << 24);
			}
			// extract all packets with the specified udp port 
			else if (strcmp(argv[i], "--extract-port") == 0)
			{
				s_ExtractPortEnable 	= true;
				s_ExtractPortMin		= atoi(argv[i+1]); 
				s_ExtractPortMax		= atoi(argv[i+2]); 
				i+= 2;

				fprintf(stderr, "    extract port range: %i-%i\n", s_ExtractPortMin, s_ExtractPortMax);
			}
			// extract the specified flow as tcp stream
			else if (strcmp(argv[i], "--extract-tcp") == 0)
			{
				u32 FlowID 			= atoi(argv[i+1]); 
				s_ExtractTCPEnable 	= true;					
				s_ExtractTCPFlow[ FlowID ] = 1;
				i++;

				fprintf(stderr, "     extract tcp flow %i\n", FlowID);
			}
			// extract all tcp flows with the matching port 
			else if (strcmp(argv[i], "--extract-tcp-port") == 0)
			{
				u32 PortMin 			= atoi(argv[i+1]);
				u32 PortMax 			= atoi(argv[i+2]);
				s_ExtractTCPPortEnable 	= true;					
				s_ExtractTCPPortMin 	= PortMin; 
				s_ExtractTCPPortMax 	= PortMax; 
				i += 2;	

				fprintf(stderr, "     extract all tcp flow with port %i-%i\n", PortMin, PortMax);
			}
			// extract all tcp flows 
			else if (strcmp(argv[i], "--extract-tcp-all") == 0)
			{
				s_ExtractTCPPortEnable 	= true;					
				s_ExtractTCPPortMin 	= 0; 
				s_ExtractTCPPortMax 	= 0x10000; 
				fprintf(stderr, "    extract all tcp flow with port %i-%i\n", s_ExtractTCPPortMin, s_ExtractTCPPortMax);
			}
			// disable port range 
			else if (strcmp(argv[i], "--disable-tcp-port") == 0)
			{
				u32 PortMin 			= atoi(argv[i+1]);
				u32 PortMax 			= atoi(argv[i+2]);
				s_DisableTCPPortMin[s_DisableTCPPortCnt] = PortMin; 
				s_DisableTCPPortMax[s_DisableTCPPortCnt] = PortMax; 
				s_DisableTCPPortCnt++;
				assert(s_DisableTCPPortCnt < s_DisableTCPPortCntMax);

				i += 2;	

				fprintf(stderr, "    disable tcp extraction on ports [%i] %i-%i\n", s_DisableTCPPortCnt-1, PortMin, PortMax);
			}
			// extract udp flows within the specified range to individual files
			else if (strcmp(argv[i], "--extract-udp-port") == 0)
			{
				u32 PortMin 			= atoi(argv[i+1]);
				u32 PortMax 			= atoi(argv[i+2]);
				s_ExtractUDPPortEnable 	= true;					
				s_ExtractUDPPortMin 	= PortMin; 
				s_ExtractUDPPortMax 	= PortMax; 
			 	i += 2;	

				fprintf(stderr, "    extract all udp flow`s with port %i-%i\n", PortMin, PortMax);
			}
			// extract udp all ports 
			else if (strcmp(argv[i], "--extract-udp-all") == 0)
			{
				s_ExtractUDPPortEnable 	= true;					
				s_ExtractUDPPortMin 	= 0; 
				s_ExtractUDPPortMax 	= 65535; 

				fprintf(stderr, "    extract all udp flows\n");
			}
			// disable port range 
			else if (strcmp(argv[i], "--disable-udp-port") == 0)
			{
				u32 PortMin 			= atoi(argv[i+1]);
				u32 PortMax 			= atoi(argv[i+2]);
				s_DisableUDPPortMin[s_DisableUDPPortCnt] = PortMin; 
				s_DisableUDPPortMax[s_DisableUDPPortCnt] = PortMax; 
				s_DisableUDPPortCnt++;
				assert(s_DisableUDPPortCnt < s_DisableUDPPortCntMax);

				i += 2;	

				fprintf(stderr, "    disable UDP extraction on ports [%i] %i-%i\n", s_DisableUDPPortCnt-1, PortMin, PortMax);
			}

			// input is from stdin 
			else if (strcmp(argv[i], "--stdin") == 0)
			{
				TCPOutputFileName 	= "stdin"; 
				UDPOutputFileName 	= "stdin"; 
				FileStdin 		= true;
				fprintf(stderr, "    reading PCAP from stdin\n");
			}
			// minimum number of packets 
			else if (strcmp(argv[i], "--flow-packet-min") == 0)
			{
				s_FlowListPacketMin = atoi(argv[i+1]);
				fprintf(stderr, "    minimum packet count %lli\n", s_FlowListPacketMin);
			}
			// display flow info
			else if (strcmp(argv[i], "--disable-display") == 0)
			{
				s_EnableFlowDisplay = false;
			}
			// enable tcp header output 
			else if (strcmp(argv[i], "--tcpheader") == 0)
			{
				g_EnableTCPHeader =true;
				fprintf(stderr, "    enabling output TCP header\n");
			}
			// enable udp header output 
			else if (strcmp(argv[i], "--udpheader") == 0)
			{
				g_EnableUDPHeader =true;
				fprintf(stderr, "    enabling output UDP header\n");
			}

			// UDP output file
			else if (strcmp(argv[i], "--output-udp") == 0)
			{
				UDPOutputFileName = argv[i+1];
				i++;
				fprintf(stderr, "    writing UDP PCAP to [%s]\n", UDPOutputFileName);
			}
			// TCP output file
			else if (strcmp(argv[i], "--output-tcp") == 0)
			{
				TCPOutputFileName = argv[i+1];
				i++;
				fprintf(stderr, "    writing TCP PCAP to [%s]\n", TCPOutputFileName);
			}
			// pin to a specific CPU
			else if (strcmp(argv[i], "--cpu") == 0)
			{
				u32 CPU 			= atoi(argv[i+1]);
				i++;

				// pin to a thread
				cpu_set_t	MainCPUS;
				CPU_ZERO(&MainCPUS);
				CPU_SET(CPU, &MainCPUS);
				pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &MainCPUS);
			}
			// minimum flow file size creation 
			else if (strcmp(argv[i], "--flow-size-min") == 0)
			{
				u32 FlowFileSizeMin	= atoi(argv[i+1]);
				i++;

				fFile_SizeMin(FlowFileSizeMin);

				fprintf(stderr, "    minimum flow file size %i B\n", FlowFileSizeMin);
			}
			// force flushing after each write 
			else if (strcmp(argv[i], "--flow-flush") == 0)
			{
				fFile_ForceFlush();
				fprintf(stderr, "    flow force flushing\n"); 
			}
			else if (strcmp(argv[i], "--verbose") == 0)
			{
				fprintf(stderr, "    enable verbose mode\n");
				g_Verbose = true;
			}
			else if (strcmp(argv[i], "--metamako") == 0)
			{
				fprintf(stderr, "    enable metamako timestamping\n");
				g_EnableMetamako = true;
			}
			else
			{
				fprintf(stderr, "    unknown option [%s]\n", argv[i]);
				return 0;
			}
		}
	}

	// needs atleast 2 files
	if (!(FileStdin) && (FileNameListPos <= 0))
	{
		print_usage();
		return 0;
	}

	if (FileStdin)	strcpy(s_FlowLogPath, "capture"); 
	else			strcpy(s_FlowLogPath, FileNameList[0]); 

	if (s_FlowExtractEnable && s_ExtractTCPEnable)
	{
		fprintf(stderr, "can not extract flow and tcp at the same time\n");
		return 0;
	}
	if (s_ExtractTCPEnable && (!TCPOutputFileName))
	{
		fprintf(stderr, "specify tcp extract path --output-tcp <path>\n");
		return 0;
	}

	// open output file
	FILE* OutPCAP = NULL;
	if (TCPOutputFileName && (!s_ExtractTCPEnable) )
	{
		OutPCAP = fopen(TCPOutputFileName, "w");
		if (OutPCAP == NULL)
		{
			fprintf(stderr, "failed to open output file [%s]\n", TCPOutputFileName);
			return 0;
		}

		PCAPHeader_t Header;
		Header.Magic 	= PCAPHEADER_MAGIC_NANO;
		Header.Major 	= PCAPHEADER_MAJOR;
		Header.Minor 	= PCAPHEADER_MINOR;
		Header.TimeZone = 0;
		Header.SigFlag	= 0;
		Header.SnapLen	= 8192;
		Header.Link		= PCAPHEADER_LINK_ETHERNET;

		fwrite(&Header, sizeof(Header), 1, OutPCAP);
	}
	
	// open flow log file 
	if (s_EnableFlowLog)
	{
		char Path[1024];
		sprintf(Path, "%s.flow", s_FlowLogPath);
		s_FlowLogFile = fopen(Path, "w");
		if (!s_FlowLogFile )
		{
			fprintf(stderr, "failed to create flow log\n");
			return 0; 
		}
	}

	// calcuate tsc frequency
	CycleCalibration();
	setlocale(LC_NUMERIC, "");

	// get timezone offset
  	time_t t = time(NULL);
	struct tm lt = {0};

	localtime_r(&t, &lt);
	s_TimeZoneOffset = lt.tm_gmtoff * 1e9;

	s_FlowIndex = (u32*)malloc( sizeof(u32)*(1ULL<<s_FlowIndexBits));
	assert(s_FlowIndex  != NULL);
	memset(s_FlowIndex, 0, sizeof(u32)*(1ULL<<s_FlowIndexBits));
	g_TotalMemory 		+= sizeof(u32)*(1ULL<<s_FlowIndexBits);
	s_FlowIndexMask		= (1<< s_FlowIndexBits) - 1;

	s_FlowList 			= (FlowHash_t*)malloc( sizeof(FlowHash_t) * s_FlowListMax ); 
	memset(s_FlowList, 0, sizeof(FlowHash_t) * s_FlowListMax );
	assert(s_FlowList != NULL);
	g_TotalMemory 		+= sizeof(FlowHash_t) * s_FlowListMax;
	
	// open pcap diff files
	PCAPFile_t* PCAPFile = OpenPCAP(FileNameList[0], FileStdin);	
	if (!PCAPFile) return 0;

	// init tcp reassembly
	/*
	if (s_ExtractTCPEnable)
	{
		for (int i=0; i < s_FlowExtractMax; i++)
		{
			if (s_ExtractTCP[i]j
			{
				char Path[256];
				u32 FlowID = i; 

				sprintf(Path, "%s.tcpflow.%i", TCPOutputFileName, FlowID);
				s_ExtractTCP[i] = fTCPStream_Init(kMB(128), Path, FlowID, 0);
			}
		}
	}
	*/

	// clear tcp output
	memset(s_ExtractTCP, 0, sizeof(s_ExtractTCP));
	printf("[%30s] FileSize: %lliGB\n", PCAPFile->Path, PCAPFile->Length / kGB(1));

	u64 TotalByte 		= 0;
	u64 TotalPkt 		= 0;
	u64 NextPrintTSC 	= 0;
	u64 StartTSC		= rdtsc();	
	u64 OutputByte		= 0;
	u64 OutputTCPByte	= 0;
	u64 OutputUDPByte	= 0;
	while (true)
	{
		fProfile_Start(0, "Top");

		fProfile_Start(1, "Fetch");

		PCAPPacket_t* Pkt = ReadPCAP(PCAPFile); 
		if (!Pkt)
		{
			fprintf(stderr, "no more packets exiting\n");
			break;
		}

		// invalid packet
		if (Pkt->Length 		== 0) break;
		if (Pkt->LengthCapture 	== 0) break;

		fProfile_Stop(1);
		fProfile_Start(2, "Decode");

		PCAPFile->TS = PCAPTimeStamp(Pkt);

		u32 HashLength = 0;
		FlowHash_t  Flow;

		fEther_t * Ether = PCAPETHHeader(Pkt);
		switch (swap16(Ether->Proto))
		{
		case ETHER_PROTO_IPV4:
		{
			IP4Header_t* IP4 = PCAPIP4Header(Pkt); 
			u32 IPOffset = (IP4->Version & 0x0f)*4; 
			switch (IP4->Proto)
			{
			case IPv4_PROTO_TCP:
			{
				if (s_ExtractTCPPortEnable)
				{
					TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);

					memset(&Flow, 0, sizeof(Flow));

					Flow.Type = FLOW_TYPE_TCP;

					TCPHash_t* TCPHash = (TCPHash_t*)Flow.Data;
					memset(TCPHash, 0, 64);

					memcpy(TCPHash->MACDst, Ether->Dst, 6);
					memcpy(TCPHash->MACSrc, Ether->Src, 6);

					TCPHash->IPSrc = IP4->Src;
					TCPHash->IPDst = IP4->Dst;

					TCPHash->PortSrc = swap16(TCP->PortSrc); 
					TCPHash->PortDst = swap16(TCP->PortDst); 

					TCPHash->DeviceID 	= 0; 
					TCPHash->DevicePort = 0; 

					if (g_EnableMetamako)
					{
						// metamako footer
						Metamako_t* MFooter = PCAPMetamako(Pkt); 

						TCPHash->DeviceID 	= swap16(MFooter->DeviceID);
						TCPHash->DevicePort = MFooter->PortID;
					}

					HashLength = 64; 

					// mark tcp SYN/SYNACK sequence numbers for duplex matching
					if (TCP_FLAG_SYN(TCP->Flags) & (!TCP_FLAG_ACK(TCP->Flags)))
					{
						// syn seq no 
						Flow.TCPSeqNo = swap32(TCP->SeqNo);
					}
					if (TCP_FLAG_SYN(TCP->Flags) & (TCP_FLAG_ACK(TCP->Flags)))
					{
						// syn.ack ack no (syn.ack bumps it by 1)
						Flow.TCPSeqNo = swap32(TCP->AckNo) -1;
					}
				}
			}
			break;

			case IPv4_PROTO_UDP: 
			{
				if (s_ExtractUDPPortEnable)
				{
					UDPHeader_t* UDP = (UDPHeader_t*)( ((u8*)IP4) + IPOffset);

					memset(&Flow, 0, sizeof(Flow));

					Flow.Type = FLOW_TYPE_UDP;

					UDPHash_t* UDPHash = (UDPHash_t*)Flow.Data;
					memset(UDPHash, 0, 64);

					memcpy(UDPHash->MACDst, Ether->Dst, 6);
					memcpy(UDPHash->MACSrc, Ether->Src, 6);

					UDPHash->IPSrc = IP4->Src;
					UDPHash->IPDst = IP4->Dst;

					UDPHash->PortSrc = swap16(UDP->PortSrc); 
					UDPHash->PortDst = swap16(UDP->PortDst); 

					UDPHash->DeviceID 	= 0; 
					UDPHash->DevicePort = 0; 
/*
					if (g_EnableMetamako)
					{
						// metamako footer
						Metamako_t* MFooter = PCAPMetamako(Pkt); 

						UDPHash->DeviceID 	= swap16(MFooter->DeviceID);
						UDPHash->DevicePort = MFooter->PortID;
					}
*/
					HashLength = 64; 
				}
			}
			break;

			default:
				//printf("ipv4 %x\n", IP4->Proto);
				break;
			}
		}
		break;

		default:
			//printf("proto: %08x\n", swap16(Ether->Proto) );
			break;
		}

		fProfile_Stop(2);

		// if its valid TCP or UDP data
		if (HashLength != 0)
		{
			fProfile_Start(3, "FlowAdd");
			u32 FlowID = 0;
			if (HashLength > 0)
			{
				FlowID = FlowAdd(&Flow, Pkt->Length, PCAPFile->TS);
			}

			if ((FlowID != 0) && s_FlowExtract[ FlowID ])
			{
				if (OutPCAP)
				{
					fwrite(Pkt, sizeof(PCAPPacket_t) + Pkt->LengthCapture, 1, OutPCAP);
					OutputByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				}
			}
			fProfile_Stop(3);

			// extract all tcp flows with the specified port range
			fProfile_Start(4, "TCP Flow");
			if (Flow.Type == FLOW_TYPE_TCP)
			{
				TCPHeader_t* TCPHeader 	= PCAPTCPHeader(Pkt);
				TCPHash_t* TCP 			= (TCPHash_t*)Flow.Data;

				bool Output = false; 
				// tcp port ranges
				if (s_ExtractTCPPortEnable)
				{
					Output |= (TCP->PortSrc >= s_ExtractTCPPortMin) && (TCP->PortSrc <= s_ExtractTCPPortMax);
					Output |= (TCP->PortDst >= s_ExtractTCPPortMin) && (TCP->PortDst <= s_ExtractTCPPortMax);

					// disable port range
					for (int d=0; d < s_DisableTCPPortCnt; d++)
					{
						if ((TCP->PortSrc >= s_DisableTCPPortMin[d]) && (TCP->PortSrc <= s_DisableTCPPortMax[d]))
						{
							Output = false;	
						}
						if ((TCP->PortDst >= s_DisableTCPPortMin[d]) && (TCP->PortDst <= s_DisableTCPPortMax[d]))
						{
							Output = false;	
						}
					}
				}
				// specific flow id`s
				if (s_ExtractTCPEnable && s_ExtractTCPFlow[FlowID])
				{
					Output = true;
				}
					
				if (Output)
				{
					// new flow ? 	
					struct TCPStream_t* Stream = s_ExtractTCP[FlowID];
					if (Stream == NULL)
					{
						char FileName[1024];
						sprintf(FileName, "%s_%02x:%02x:%02x:%02x:%02x:%02x->%02x:%02x:%02x:%02x:%02x:%02x_%3i.%3i.%3i.%3i->%3i.%3i.%3i.%3i_%6i->%6i_%05i_%02i",
								TCPOutputFileName,
								
								TCP->MACSrc[0],	
								TCP->MACSrc[1],	
								TCP->MACSrc[2],	
								TCP->MACSrc[3],	
								TCP->MACSrc[4],	
								TCP->MACSrc[5],	
		
								TCP->MACDst[0],	
								TCP->MACDst[1],	
								TCP->MACDst[2],	
								TCP->MACDst[3],	
								TCP->MACDst[4],	
								TCP->MACDst[5],	

								TCP->IPSrc.IP[0],
								TCP->IPSrc.IP[1],
								TCP->IPSrc.IP[2],
								TCP->IPSrc.IP[3],

								TCP->IPDst.IP[0],
								TCP->IPDst.IP[1],
								TCP->IPDst.IP[2],
								TCP->IPDst.IP[3],

								TCP->PortSrc,
								TCP->PortDst,

								TCP->DeviceID,
								TCP->DevicePort
						);

						Stream = fTCPStream_Init(kMB(128), FileName, FlowID, Flow.Hash, PCAPFile->TS);
						s_ExtractTCP[FlowID] = Stream;
					}
					if (Stream == NULL)
					{
						printf("invalid flwo: %i\n", FlowID);
					}
					assert(Stream != NULL);

					// add packet to the stream
			fProfile_Start(6, "TCP PktAdd");

					u32 TCPPayloadLength = 0;
					u8*	TCPPayload	= PCAPTCPPayload(Pkt, &TCPPayloadLength); 
					fTCPStream_PacketAdd(Stream, PCAPFile->TS, TCPHeader, TCPPayloadLength, TCPPayload);

			fProfile_Stop(6);

					OutputTCPByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				}
			}
			fProfile_Stop(4);

			// extract all udp flows  
			if (s_ExtractUDPPortEnable && (Flow.Type == FLOW_TYPE_UDP))
			{
				UDPHeader_t* UDPHeader 	= PCAPUDPHeader(Pkt);
				UDPHash_t* UDP 			= (UDPHash_t*)Flow.Data;

				bool Output = false; 
				Output |= (UDP->PortSrc >= s_ExtractUDPPortMin) && (UDP->PortSrc <= s_ExtractUDPPortMax);
				Output |= (UDP->PortDst >= s_ExtractUDPPortMin) && (UDP->PortDst <= s_ExtractUDPPortMax);

				// disable port range
				for (int d=0; d < s_DisableUDPPortCnt; d++)
				{
					if ((UDP->PortSrc >= s_DisableUDPPortMin[d]) && (UDP->PortSrc <= s_DisableUDPPortMax[d]))
					{
						Output = false;	
					}
					if ((UDP->PortDst >= s_DisableUDPPortMin[d]) && (UDP->PortDst <= s_DisableUDPPortMax[d]))
					{
						Output = false;	
					}
				}

				if (Output)
				{
					// new flow ? 	
					struct UDPStream_t* Stream = s_ExtractUDP[FlowID];
					if (Stream == NULL)
					{
						char FileName[257];
						sprintf(FileName, "%s_%02x:%02x:%02x:%02x:%02x:%02x->%02x:%02x:%02x:%02x:%02x:%02x_%3i.%3i.%3i.%3i->%3i.%3i.%3i.%3i_%6i->%6i_%05i_%02i",
								UDPOutputFileName,

								UDP->MACSrc[0],	
								UDP->MACSrc[1],	
								UDP->MACSrc[2],	
								UDP->MACSrc[3],	
								UDP->MACSrc[4],	
								UDP->MACSrc[5],	
		
								UDP->MACDst[0],	
								UDP->MACDst[1],	
								UDP->MACDst[2],	
								UDP->MACDst[3],	
								UDP->MACDst[4],	
								UDP->MACDst[5],	

								UDP->IPSrc.IP[0],
								UDP->IPSrc.IP[1],
								UDP->IPSrc.IP[2],
								UDP->IPSrc.IP[3],

								UDP->IPDst.IP[0],
								UDP->IPDst.IP[1],
								UDP->IPDst.IP[2],
								UDP->IPDst.IP[3],

								UDP->PortSrc,
								UDP->PortDst,

								UDP->DeviceID,
								UDP->DevicePort
						);
						Stream = fUDPStream_Init(FileName, FlowID, PCAPFile->TS);
						s_ExtractUDP[FlowID] = Stream;
					}
					assert(Stream != NULL);

					fUDPStream_Add(Stream, PCAPFile->TS, Pkt, UDPHeader);
					OutputUDPByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				}
			}

			// extract all IP`s that match the mask
			if (s_ExtractIPEnable)
			{
				IP4Header_t* IP4 = PCAPIP4Header(Pkt); 

				bool Extract = false;

				if ((IP4->Src.IP4 & s_ExtractIPMask) == s_ExtractIPMatch)
				{
					Extract = true;
				}
				if ((IP4->Dst.IP4 & s_ExtractIPMask) == s_ExtractIPMatch)
				{
					Extract = true;
				}

				if (Extract && OutPCAP)
				{
					fwrite(Pkt, sizeof(PCAPPacket_t) + Pkt->LengthCapture, 1, OutPCAP);
					OutputByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				}
			}

			// extract UDP port
			if (s_ExtractPortEnable)
			{
				bool Extract = false;
				u32 PortSrc = 0;
				u32 PortDst = 0;
				if (Flow.Type == FLOW_TYPE_UDP)
								
				{
					UDPHeader_t* UDP = PCAPUDPHeader(Pkt); 

					PortSrc = swap16(UDP->PortSrc);
					PortDst = swap16(UDP->PortDst);
				}
				if (Flow.Type == FLOW_TYPE_TCP)
				{
					TCPHeader_t* TCP = PCAPTCPHeader(Pkt); 

					PortSrc = swap16(TCP->PortSrc);
					PortDst = swap16(TCP->PortDst);
				}

				if ((s_ExtractPortMin <= PortSrc) && 
					(PortSrc <= s_ExtractPortMax))
				{
					Extract = true;
				}

				if ((s_ExtractPortMin <= PortDst) && 
					(PortDst <= s_ExtractPortMax))
				{
					Extract = true;
				}
				if (Extract && OutPCAP)
				{
					fwrite(Pkt, sizeof(PCAPPacket_t) + Pkt->LengthCapture, 1, OutPCAP);
					OutputByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				}
			}
		}

		TotalPkt++;
		TotalByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;

		fProfile_Stop(0);

		if (rdtsc() > NextPrintTSC)
		{
			u64 TSC = rdtsc();
			NextPrintTSC = TSC + 3e9;

			static u64 LastTSC = 0;
			double dT = tsc2ns(TSC - LastTSC) / 1e9;
			LastTSC = TSC;

			static u64 LastByte = 0;
			double Bps = (TotalByte - LastByte) / dT;
			LastByte = TotalByte;

			double TotalTime = tsc2ns(TSC - StartTSC);

			double MeanHashDepth = s_FlowIndexDepthS1 * inverse(s_FlowIndexDepthS0);

			u64 TSf = PCAPFile->TS; 
			fprintf(stderr, "[%s %.3f%%] ", FormatTS(TSf), PCAPFile->ReadPos / (double)PCAPFile->Length); 
			fprintf(stderr, "%5.f Min ", TotalTime / 60e9);
			fprintf(stderr, "Flows:%i ", s_FlowListPos);
			fprintf(stderr, "%lli Pkts %8.3fGbps : %.2fGB ",
					TotalPkt,
					(8.0*Bps) / 1e9,
					TotalByte / 1e9
			);
			fprintf(stderr, "Out:%.2fGB ", OutputByte / 1e9);
			fprintf(stderr, "OutTCP:%.2fGB ", OutputTCPByte / 1e9);
			fprintf(stderr, "OutUDP:%.2fGB ", OutputUDPByte / 1e9);
			fprintf(stderr, "Memory:%.2fMB ", g_TotalMemory / 1e6); 
			fprintf(stderr, "MemoryTCP:%.2fMB ", g_TotalMemoryTCP / 1e6); 
			fprintf(stderr, "HashDepth:%i (%.3f)  ", s_FlowIndexDepthMax, MeanHashDepth);

			fprintf(stderr, "\n");

			// push everything out (e.g. for long runs constantly push to log file)
			fflush(stdout);
			fflush(stderr);
			if (TotalPkt > s_MaxPackets)
			{
				fprintf(stderr, "Maxpackets reached exiting: %lli %lli\n", TotalPkt, s_MaxPackets);
				break;
			}

			static int cnt = 0;
			if (cnt++ > 10)
			{
				cnt = 0;
				fProfile_Dump(0);

				// dump stats
				fTCPStream_Dump(PCAPFile->TS);
			}
/*
			// flush tcp/streams to disk
			static u32 FlowFlush = 0;

			// only flush 5K flows at a time
			u32 FlushCnt = (s_FlowListMax > 5000) ? 5000 : s_FlowListMax;
			for (int i=0; i < FlushCnt; i++)
			{
				if (s_ExtractTCP[FlowFlush])
				{
					//fprintf(stderr, "[%i] TCP Flush\n", i);
					fTCPStream_Flush(s_ExtractTCP[FlowFlush]);
				}
				FlowFlush++;
				if (FlowFlush >= s_FlowListMax) FlowFlush = 0;
			}
*/
		}
	}
	fprintf(stderr, "parse done TotalPkts:%lli\n", TotalPkt);
	fflush(stderr);

	// close output streams
	for (int i=0; i < s_FlowListMax; i++)
	{
		if (s_ExtractTCP[i])
		{
			//fprintf(stderr, "[%i] TCP Close\n", i);
			fTCPStream_Close(s_ExtractTCP[i]);
		}
	}

	if (OutPCAP) fclose(OutPCAP);
	if (s_EnableFlowDisplay) PrintHumanFlows();	
}

/* vim: set ts=4 sts=4 */
