//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015, fmad engineering llc 
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

#include "fTypes.h"
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

	u64		TimeScale;		// 1000ns for usec pcap, 1ns for nano pcap
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

	u32		Type;				// what kind of flow is this

	u64		PktCnt;				// number of packets in this flow
	u64		Bytes;				// number of bytes in this flow

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

} TCPHash_t;

typedef struct
{
	u8		MACSrc[6];
	u8		MACDst[6];
	IP4_t	IPSrc;
	IP4_t	IPDst;

	u16		PortSrc;
	u16		PortDst;

} UDPHash_t;

double TSC2Nano = 0;

//---------------------------------------------------------------------------------------------
// tunables

static u64		s_MaxPackets			= (1ULL<<63);	// max number of packets to process
static s64		s_TimeZoneOffset		= 0;			// local timezone

//---------------------------------------------------------------------------------------------
// first level index 

static u32*		s_FlowIndex;							// 24b index into first level list 

static FlowHash_t*			s_FlowList;							// statically allocated max number of flows 
static u32					s_FlowListPos = 1;					// current allocated flow
static u32					s_FlowListMax;						// max number of flows

static u64					s_FlowListPacketMin = 0;			// minimum number of packets to show entry for

static u8					s_FlowExtract[1024*1024];			// boolean to extract the specified flow id
static bool					s_FlowExtractEnable 	= false;	// indicaes flow extraction 
static u32					s_FlowExtractMax		= 1024*1024;

static u32					s_ExtractTCPEnable 		= false;	// request extraction of tcp stream
static u32					s_ExtractTCPFlowID 		= 0;		// which flow to extract

static bool					s_ExtractTCPPortEnable 	= false;	// extract all tcp flows with the specified port number
static u32					s_ExtractTCPPortMin		= 0;
static u32					s_ExtractTCPPortMax		= 0;
static struct TCPStream_t* 	s_ExtractTCP[1024*1024]; 			// list of tcp stream extraction objects 

static bool					s_ExtractUDPPortEnable 	= false;	// extract all UDP flows within the specified port range 
static u32					s_ExtractUDPPortMin		= 0;
static u32					s_ExtractUDPPortMax		= 0;
static struct UDPStream_t*	s_ExtractUDP[1024*1024];

static bool					s_ExtractIPEnable		= false;	// extract an IP range into a seperate pcap file
static u32					s_ExtractIPMask			= 0;		// /32 mask
static u32					s_ExtractIPMatch		= 0;		// match 

static bool					s_ExtractPortEnable		= false;	// extract TCP/UDP port range to a seperate pcap file 
static u32					s_ExtractPortMin		= 0;		// min port range 
static u32					s_ExtractPortMax		= 0;		// max port range 

static bool					s_EnableFlowDisplay 	= true;		// print full flow information
bool						g_EnableTCPHeader 		= false;	// output packet header in tcp stream

//---------------------------------------------------------------------------------------------
// mmaps a pcap file in full
static PCAPFile_t* OpenPCAP(char* Path, bool EnableStdin)
{
	PCAPFile_t* F = (PCAPFile_t*)malloc( sizeof(PCAPFile_t) );
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
		F->Length 	= 1e12;
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
	}

	switch (Header->Magic)
	{
	case PCAPHEADER_MAGIC_USEC: F->TimeScale = 1000; break;
	case PCAPHEADER_MAGIC_NANO: F->TimeScale = 1; break;
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
	if (ret != sizeof(PCAPPacket_t)) return NULL;

	if (PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture > PCAP->Length) return NULL; 

	ret = fread(Pkt+1, 1, Pkt->LengthCapture, PCAP->F);
	if (ret != Pkt->LengthCapture) return NULL;

	PCAP->ReadPos += Pkt->LengthCapture;
	return Pkt;
}

//---------------------------------------------------------------------------------------------
// helpers for network formating 
static u64 PCAPTimeStamp(PCAPPacket_t* Pkt)
{
	return s_TimeZoneOffset + Pkt->Sec * k1E9 + Pkt->NSec;
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

//---------------------------------------------------------------------------------------------
static u32 FlowHash(u32 Type, u8* Payload, u32 Length)
{
	// DEK packets usually have enough entropy for this to be enough 
	u32 Hash = Type; 
	for (int i=0; i < Length; i++)
	{
		Hash = ((Hash << 5ULL) ^ (Hash >> (32-5))) ^ (u64)Payload[i];
	}
	return Hash;
}

//---------------------------------------------------------------------------------------------

static u32 FlowAdd(FlowHash_t* Flow, u32 PktLength, u64 TS) 
{
	if (s_FlowListPos >= s_FlowExtractMax) return 0;


	FlowHash_t* F = NULL; 

	// first level has is 24b index, followed by list of leaf nodes

	u32 Hash 	= FlowHash(Flow->Type, (u8*)Flow->Data, 64);
	u32 Index 	= Hash & 0x00ffffff;

	u32 FlowIndex = 0;

	if (s_FlowIndex[Index] != 0)
	{
		F = s_FlowList +  s_FlowIndex[Index];
		bool Found = false;
		for (int t=0; t < 1e6; t++)
		{
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
		}
	}
	else
	{
		F = &s_FlowList[ s_FlowListPos++ ];
		assert(s_FlowListPos < s_FlowListMax);

		memcpy(F, Flow, sizeof(FlowHash_t));
		F->Next = 0;

		s_FlowIndex[Index] = F - s_FlowList; 
	}

	// update stats

	F->PktCnt++;
	F->Bytes += PktLength;

	return F - s_FlowList;
}


//---------------------------------------------------------------------------------------------
static void PrintMAC(u8* MAC)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
			MAC[0],
			MAC[1],
			MAC[2],
			MAC[3],
			MAC[4],
			MAC[5]
		  );
}
static void PrintIP4(IP4_t IP)
{
	printf("%3i.%3i.%3i.%3i", IP.IP[0], IP.IP[1], IP.IP[2], IP.IP[3]); 
}

//---------------------------------------------------------------------------------------------

static void PrintFlowTCP(FlowHash_t* F, u32 FlowID, u32 FlowCnt)
{

	TCPHash_t* TCP = (TCPHash_t*)F->Data;
	printf("%5i FlowID: %8i | TCP  ", FlowCnt, FlowID); 	
	PrintMAC(TCP->MACSrc);
	printf(" -> ");
	PrintMAC(TCP->MACDst);

	printf(" | ");
	PrintIP4(TCP->IPSrc);
	printf(" -> ");
	PrintIP4(TCP->IPDst);

	printf(" | %6i -> %6i ", TCP->PortSrc, TCP->PortDst);

	printf(" | ");
	printf(" %'16lld Pkts ", F->PktCnt);
	printf(" %'16lli Bytes ", F->Bytes);

	printf("\n");

}

//---------------------------------------------------------------------------------------------

static void PrintFlowUDP(FlowHash_t* F, u32 FlowID, u32 FlowCnt)
{

	UDPHash_t* UDP = (UDPHash_t*)F->Data;
	printf("%5i FlowID: %8i | UDP  ", FlowCnt, FlowID); 	
	PrintMAC(UDP->MACSrc);
	printf(" -> ");
	PrintMAC(UDP->MACDst);

	printf(" | ");
	PrintIP4(UDP->IPSrc);
	printf(" -> ");
	PrintIP4(UDP->IPDst);

	printf(" | %6i -> %6i ", UDP->PortSrc, UDP->PortDst);

	printf(" | ");
	printf(" %'16lld Pkts ", F->PktCnt);
	printf(" %'16lli Bytes ", F->Bytes);

	printf("\n");

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
					case FLOW_TYPE_TCP: PrintFlowTCP(F, i, FlowCnt); break;
					case FLOW_TYPE_UDP: PrintFlowUDP(F, i, FlowCnt); break;
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
	fprintf(stderr, "  -o <filename>                            | write output to the specified file name\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  --packet-max  <number>                   | only process the first <number> packets\n");
	fprintf(stderr, "  --extract <number>                       | extract FlowID <number> into the output PCAP file\n");
	fprintf(stderr, "  --extract-tcp <number>                   | extract FlowID <number> as a TCP stream to the output file name\n"); 
	fprintf(stderr, "  --extract-tcp-port <min port> <max port> | extract all TCP flows with the specified port in src or dest\n");
	fprintf(stderr, "  --stdin                                  | read pcap from stdin. e.g. zcat capture.pcap | pcap_flow --stdin\n"); 
	fprintf(stderr, "  --flow-packet-min <number>               | minimum packet count to display flow info\n"); 
	fprintf(stderr, "  --disable-display                        | do not display flow information to stdout\n");
	fprintf(stderr, "\n");
}

//---------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	int 	FileNameListPos = 0;
	char 	FileNameList[16][256];
	int		FileStdin = false;

	char* 	OutputFileName = NULL;

	memset(s_FlowExtract, 0, sizeof(s_FlowExtract));

	for (int i=1; i < argc; i++)
	{
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
				fprintf(stderr, "setting maximum number of packets to %lli\n", s_MaxPackets);
			}
			else if (strcmp(argv[i], "--extract") == 0)
			{
				u32 FlowID = atoi(argv[i+1]); 
				if (FlowID >= sizeof(s_FlowExtract))
				{
					fprintf(stderr, "flow overflow\n");
					return 0;
				}
				s_FlowExtract[ FlowID ] = 1;
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

				fprintf(stderr, "extract ip range %i.%i.%i.%i/%i.%i.%i.%i\n", 
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

				fprintf(stderr, "extract port range: %i-%i\n", s_ExtractPortMin, s_ExtractPortMax);
			}

			// extract the specified flow as tcp stream
			else if (strcmp(argv[i], "--extract-tcp") == 0)
			{
				u32 FlowID 			= atoi(argv[i+1]); 
				s_ExtractTCPEnable 	= true;					
				s_ExtractTCPFlowID 	= FlowID;					
				i++;

				fprintf(stderr, "extract tcp flow %i\n", FlowID);
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

				fprintf(stderr, "extract all tcp flow with port %i-%i\n", PortMin, PortMax);
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

				fprintf(stderr, "extract all udp flow`s with port %i-%i\n", PortMin, PortMax);
			}
			// input is from stdin 
			else if (strcmp(argv[i], "--stdin") == 0)
			{
				OutputFileName 	= "stdin"; 
				FileStdin 		= true;
				fprintf(stderr, "writing PCAP to [%s]\n", OutputFileName);
			}
			// minimum number of packets 
			else if (strcmp(argv[i], "--flow-packet-min") == 0)
			{
				s_FlowListPacketMin = atoi(argv[i+1]);
				fprintf(stderr, "minimum packet count %lli\n", s_FlowListPacketMin);
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
				fprintf(stderr, "enabling output tcp header\n");
			}
			// output file
			else if (strcmp(argv[i], "-o") == 0)
			{
				OutputFileName = argv[i+1];
				i++;
				fprintf(stderr, "writing PCAP to [%s]\n", OutputFileName);
			}
			else
			{
				fprintf(stderr, "unknown option [%s]\n", argv[i]);
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

	if (s_FlowExtractEnable && s_ExtractTCPEnable)
	{
		fprintf(stderr, "can not extract flow and tcp at the same time\n");
		return 0;
	}

	// open output file
	FILE* OutPCAP = NULL;
	if (OutputFileName && (!s_ExtractTCPEnable) )
	{
		OutPCAP = fopen(OutputFileName, "w");
		if (OutPCAP == NULL)
		{
			fprintf(stderr, "failed to open output file [%s]\n", OutputFileName);
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

	// calcuate tsc frequency
	CycleCalibration();

	setlocale(LC_NUMERIC, "");

	// get timezone offset

  	time_t t = time(NULL);
	struct tm lt = {0};

	localtime_r(&t, &lt);
	s_TimeZoneOffset = lt.tm_gmtoff * 1e9;

	s_FlowIndex = (u32*)malloc( sizeof(u32)*(1ULL<<24));
	memset(s_FlowIndex, 0, sizeof(u32)*(1ULL<<24));

	s_FlowListMax = 10e6;
	s_FlowList = (FlowHash_t*)malloc( sizeof(FlowHash_t) * s_FlowListMax ); memset(s_FlowList, 0, sizeof(FlowHash_t) * s_FlowListMax );
	
	// open pcap diff files

	PCAPFile_t* PCAPFile = OpenPCAP(FileNameList[0], FileStdin);	
	if (!PCAPFile) return 0;

	// init tcp reassembly
	struct TCPStream_t* TCPStream = NULL;
	if (s_ExtractTCPEnable)
	{
		TCPStream = fTCPStream_Init(kMB(128), OutputFileName, s_ExtractTCPFlowID);
		if (!TCPStream) return 0;
	}

	// clear tcp output

	memset(s_ExtractTCP, 0, sizeof(s_ExtractTCP));
	printf("[%30s] FileSize: %lliGB\n", PCAPFile->Path, PCAPFile->Length / kGB(1));

	u64 TotalByte 		= 0;
	u64 TotalPkt 		= 0;
	u64 NextPrintTSC 	= 0;
	u64 StartTSC		= rdtsc();	
	u64 OutputByte		= 0;
	while (true)
	{
		PCAPPacket_t* Pkt = ReadPCAP(PCAPFile); 
		if (!Pkt) break;

		PCAPFile->TS = PCAPTimeStamp(Pkt);

		u32 HashLength = 0;
		FlowHash_t  Flow;
		memset(&Flow, 0, sizeof(Flow));

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
				TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);

				Flow.Type = FLOW_TYPE_TCP;

				TCPHash_t* TCPHash = (TCPHash_t*)Flow.Data;
				memset(TCPHash, 0, 64);

				memcpy(TCPHash->MACDst, Ether->Dst, 6);
				memcpy(TCPHash->MACSrc, Ether->Src, 6);

				TCPHash->IPSrc = IP4->Src;
				TCPHash->IPDst = IP4->Dst;

				TCPHash->PortSrc = swap16(TCP->PortSrc); 
				TCPHash->PortDst = swap16(TCP->PortDst); 

				HashLength = 64; 
			}
			break;

			case IPv4_PROTO_UDP: 
			{
				UDPHeader_t* UDP = (UDPHeader_t*)( ((u8*)IP4) + IPOffset);

				Flow.Type = FLOW_TYPE_UDP;

				UDPHash_t* UDPHash = (UDPHash_t*)Flow.Data;
				memset(UDPHash, 0, 64);

				memcpy(UDPHash->MACDst, Ether->Dst, 6);
				memcpy(UDPHash->MACSrc, Ether->Src, 6);

				UDPHash->IPSrc = IP4->Src;
				UDPHash->IPDst = IP4->Dst;

				UDPHash->PortSrc = swap16(UDP->PortSrc); 
				UDPHash->PortDst = swap16(UDP->PortDst); 

				HashLength = 64; 
			}
			break;
			}
		}
		break;
		}

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

		if (s_ExtractTCPEnable && (FlowID == s_ExtractTCPFlowID))
		{
			TCPHeader_t* TCP = PCAPTCPHeader(Pkt); 

			u32 TCPPayloadLength = 0;
			u8*	TCPPayload	= PCAPTCPPayload(Pkt, &TCPPayloadLength); 

			fTCPStream_PacketAdd(TCPStream, PCAPFile->TS, TCP, TCPPayloadLength, TCPPayload);
		}

		// extract all tcp flows with the specified port range
		if (s_ExtractTCPPortEnable && (Flow.Type == FLOW_TYPE_TCP))
		{
			TCPHeader_t* TCPHeader 	= PCAPTCPHeader(Pkt);
			TCPHash_t* TCP 			= (TCPHash_t*)Flow.Data;

			bool Output = false; 
			Output |= (TCP->PortSrc >= s_ExtractTCPPortMin) && (TCP->PortSrc <= s_ExtractTCPPortMax);
			Output |= (TCP->PortDst >= s_ExtractTCPPortMin) && (TCP->PortDst <= s_ExtractTCPPortMax);
			
			if (Output)
			{
				// new flow ? 	
				struct TCPStream_t* Stream = s_ExtractTCP[FlowID];
				if (Stream == NULL)
				{
					char FileName[1024];
					sprintf(FileName, "%s_%02x:%02x:%02x:%02x:%02x:%02x->%02x:%02x:%02x:%02x:%02x:%02x_%3i.%3i.%3i.%3i->%3i.%3i.%3i.%3i_%6i->%6i",
							OutputFileName,
							
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
							TCP->PortDst
		  			);

					Stream = fTCPStream_Init(kMB(128), FileName, FlowID);
					s_ExtractTCP[FlowID] = Stream;
				}
				if (Stream == NULL)
				{
					printf("invalid flwo: %i\n", FlowID);
				}
				assert(Stream != NULL);

				// add packet to the stream

				u32 TCPPayloadLength = 0;
				u8*	TCPPayload	= PCAPTCPPayload(Pkt, &TCPPayloadLength); 

				fTCPStream_PacketAdd(Stream, PCAPFile->TS, TCPHeader, TCPPayloadLength, TCPPayload);
			}
		}

		// extract all udp flows  

		if (s_ExtractUDPPortEnable && (Flow.Type == FLOW_TYPE_UDP))
		{
			UDPHeader_t* UDPHeader 	= PCAPUDPHeader(Pkt);
			UDPHash_t* UDP 			= (UDPHash_t*)Flow.Data;

			bool Output = false; 
			Output |= (UDP->PortSrc >= s_ExtractUDPPortMin) && (UDP->PortSrc <= s_ExtractUDPPortMax);
			Output |= (UDP->PortDst >= s_ExtractUDPPortMin) && (UDP->PortDst <= s_ExtractUDPPortMax);

			if (Output)
			{
				// new flow ? 	
				struct UDPStream_t* Stream = s_ExtractUDP[FlowID];
				if (Stream == NULL)
				{
					char FileName[256];
					sprintf(FileName, "%s_%s_%02x:%02x:%02x:%02x:%02x:%02x->%02x:%02x:%02x:%02x:%02x:%02x_%3i.%3i.%3i.%3i->%3i.%3i.%3i.%3i_%i->%i",
							OutputFileName,

							FormatTS(PCAPFile->TS),
							
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
							UDP->PortDst
		  			);
					Stream = fUDPStream_Init(FileName, FlowID);
					s_ExtractUDP[FlowID] = Stream;
				}
				assert(Stream != NULL);

				fUDPStream_Add(Stream, PCAPFile->TS, Pkt);
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

		TotalPkt++;
		TotalByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;

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
			double ETA = PCAPFile->Length * (TotalTime / (double)TotalByte);
			double Min = (ETA - TotalTime) / 60e9;

			u64 TSf = PCAPFile->TS; 
			fprintf(stderr, "[%s %.3f%%] ", FormatTS(TSf), PCAPFile->ReadPos / (double)PCAPFile->Length); 
			fprintf(stderr, "Flows:%i ", s_FlowListPos);
			fprintf(stderr, "%.2fM Pkts %.3fGbps : %.2fGB ",
					TotalPkt / 1e6, 
					(8.0*Bps) / 1e9,
					TotalByte / 1e9
			);
			fprintf(stderr, "Out:%.2fGB ", OutputByte / 1e9);

			fprintf(stderr, "\n");
			if (TotalPkt > s_MaxPackets) break;
		}
	}
	fprintf(stderr, "parse done\n");

	if (OutPCAP) fclose(OutPCAP);
	fTCPStream_Close(TCPStream);

	if (s_EnableFlowDisplay) PrintHumanFlows();	

}

/* vim: set ts=4 sts=4 */
