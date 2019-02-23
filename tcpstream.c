//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015 fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
//
// tcp stream exporter 
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
#include <assert.h>
#include <errno.h>

#include "fTypes.h"
#include "fProfile.h"
#include "tcpstream.h"
#include "fFile.h"

//---------------------------------------------------------------------------------------------

#define MAX_TCPSEGMENT		(1024*1024)
typedef struct 
{
	u64			TS;
	u32			SeqNo;
	u32			Length;

	u8*			Payload;

} TCPBuffer_t;

typedef struct TCPStream_t 
{
	u32				ID;						// unique ID for this stream
	struct fFile_t*	File;
	u32				FlowID;
	u32				FlowHash;				// use the same has to index the tcp stream cache

	u32				SeqNo;					// current/next expected tcp seq number

	u32				BufferListPos;
	u32				BufferListMax;
	TCPBuffer_t*	BufferList[1*1024];

	char			Path[1024];				// full path 
	u64				LastTSC;				// cycle counter when this file was last accessed 
	u64				LastTS;

	bool			IsFileCreate;			// has the output file been created yet. e.g. for
											// file truncation

	u64				WritePos;				// number of bytes written to output (including stream headers)
	u32				WindowScale;			// tcp window scaling value

	bool			IsTrace;				// debug this stream

} TCPStream_t;

// public header output for each stream

#define TCPHEADER_FLAG_RESET		(1<<15)		// indicates tcp stream has been reset
#define TCPHEADER_FLAG_REASSEMBLE	(1<<14)		// indicates this payload has been re-assembled 

typedef struct
{
	u64		TS;					// timestamp of last byte	
	u16		Length;				// number of bytes in this packet
	u16		StreamID;			// unique id per flow

	u32		SeqNo;				// current tcp seq no
	u32		AckNo;				// current tcp ack no

	u32		Window;				// tcp window size in bytes
	u16		Flag;				// flags
	u16		CRC;				// checksum

} TCPOutputHeader_t;

//---------------------------------------------------------------------------------------------

extern u64			g_TotalMemory;
extern u64			g_TotalMemoryTCP;
extern bool			g_Verbose;

//---------------------------------------------------------------------------------------------

static int			s_StreamCnt		= 0;
static int			s_StreamMax		= 4*1024*1024;
static TCPStream_t* s_Stream[4*1024*1024];

extern bool			g_EnableTCPHeader;

static u64			s_TCPBufferMemoryTotal	= 0;				// total amount of gapped tcp data
static u64			s_TCPBufferPacketTotal	= 0;				// total number of packets unclaimed
static u32			s_TCPBufferMaxDepth		= 0;				// max depth of an OOO buffer

static u64			s_TotalByte 			= 0;				// total number of bytes outputed in streams
static u64			s_TotalPkt 				= 0;				// total number of packets output 

//---------------------------------------------------------------------------------------------
// converts tcpflags to our internal version
static u32 StreamTCPFlag(u32 TCPFlag)
{
	u32 Flag = 0;
/*
	// syn
	if (TCP_FLAG_SYN(TCPFlag) && (!TCP_FLAG_ACK(TCPFlag)))
	{
		Flag = TCPHEADER_FLAG_SYN;
	}
	// syn.ack
	if (TCP_FLAG_SYN(TCPFlag) && (TCP_FLAG_ACK(TCPFlag)))
	{
		Flag = TCPHEADER_FLAG_SYN | TCPHEADER_FLAG_ACK;
	}
	if (TCP_FLAG_FIN(TCPFlag))
	{
		Flag = TCPHEADER_FLAG_FIN;
	}
*/

	Flag = swap16(TCPFlag) & 0xFF;
	return Flag;
}

//---------------------------------------------------------------------------------------------

TCPStream_t* fTCPStream_Init(u64 MemorySize, char* OutputName, u32 FlowID, u32 FlowHash, u64 TS)
{
	TCPStream_t* TCPStream = malloc( sizeof( TCPStream_t) );
	assert(TCPStream != NULL);
	memset(TCPStream, 0, sizeof( TCPStream_t) );
	g_TotalMemory += sizeof( TCPStream_t);

	TCPStream->ID				= s_StreamCnt++;
	assert(s_StreamCnt < s_StreamMax);

	s_Stream[TCPStream->ID] 	= TCPStream;

	TCPStream->SeqNo 			= 0;
	TCPStream->BufferListPos 	= 0;
	TCPStream->BufferListMax 	= 1*1024;

	strncpy(TCPStream->Path, OutputName, sizeof(TCPStream->Path));
	//TCPStream->fd = -1; 
	TCPStream->File 			= NULL;

	TCPStream->FlowID 			= FlowID;
	TCPStream->FlowHash	 		= FlowHash;

	TCPStream->IsFileCreate		= false;

	TCPStream->WindowScale		= 1;

	//printf("[%s] FlowID:%i TCP Stream: [%s]\n", FormatTS(TS), FlowID, OutputName);
	return TCPStream; 
}

//---------------------------------------------------------------------------------------------

static void fTCPStream_Open(TCPStream_t* S)
{
	fProfile_Start(10, "TCP PktAdd Open");

	if (S->File == NULL)
	{
		fProfile_Start(15, "TCP IO Open");

		//S->File = fopen64(S->Path, "w+"); 
		S->File = fFile_Open(S->Path, "w+"); 
		fProfile_Stop(15);

		if (S->File == NULL) 
		{
			fprintf(stderr, "failed to create output file [%s] errno:%i (%s)\n", S->Path, errno, strerror(errno));
			exit(-1);
		}
	}

	fProfile_Stop(10);
}

//---------------------------------------------------------------------------------------------

void fTCPStream_Close(struct TCPStream_t* S)
{
	if(!S) return;

	//close(S->fd);
	//fclose(S->File);
	fFile_Close(S->File);

	memset(S, 0, sizeof(TCPStream_t));
	free(S);
}

//---------------------------------------------------------------------------------------------
// periodically flush to disk
void fTCPStream_Flush(struct TCPStream_t* S)
{
	if (!S) return;
	//fflush(S->File);
	fFile_Flush(S->File);
}

//---------------------------------------------------------------------------------------------
// write tcp header only to disk
void fTCPStream_OutputHeader(TCPStream_t* S, TCPOutputHeader_t* Header) 
{
	// ensure file is open
	fTCPStream_Open(S);	

	fProfile_Start(13, "TCP PktAdd OutputHeader");

	//int wlen = write(S->fd, &Header, sizeof(Header));
	//int wlen = fwrite(&Header, sizeof(Header), 1, S->File);
	fFile_Write(S->File, Header, sizeof(TCPOutputHeader_t));

	S->WritePos += sizeof(TCPOutputHeader_t);

	S->LastTSC = rdtsc();

	fProfile_Stop(13);
}

//---------------------------------------------------------------------------------------------

void fTCPStream_OutputPayload(TCPStream_t* S, u64 TS, u32 Length, u8* Payload, u32 Flag, u32 SeqNo, u32 AckNo, u32 WindowSize)
{
	// ensure file is open 
	fTCPStream_Open(S);	

	fProfile_Start(12, "TCP PktAdd OutputPayload");
	S->SeqNo += Length;

	int rlen;
	if (g_EnableTCPHeader)
	{
		TCPOutputHeader_t Header;
		Header.TS 		= TS;
		Header.Length 	= Length;
		Header.StreamID	= S->FlowID;
		Header.SeqNo	= SeqNo; 
		Header.AckNo	= AckNo; 
		Header.Window	= WindowSize; 
		Header.Flag		= Flag; 
		Header.CRC		= 0;
		Header.CRC		+= Header.TS;
		Header.CRC		+= Header.Length;
		Header.CRC		+= Header.StreamID;
		Header.CRC		+= Header.SeqNo;
		Header.CRC		+= Header.AckNo;
		Header.CRC		+= Header.Window;
		Header.CRC		+= Header.Flag;

		//rlen = write(S->fd, &Header, sizeof(Header));
		//rlen = fwrite(&Header, sizeof(Header), 1, S->File);
		fFile_Write(S->File, &Header, sizeof(TCPOutputHeader_t));

		S->WritePos += sizeof(TCPOutputHeader_t);
	}

	/*
	if (S->IsTrace)
	{
		for (int i=0; i < Length; i++)
		{
			if (i % 16 == 0) printf("\n");
			printf("%02x ", Payload[i]);
		}
		printf("\n");
	}
	*/


	//rlen = write(S->fd, Payload, Length);
	//rlen = fwrite(Payload, Length, 1, S->File);
	fFile_Write(S->File, Payload, Length);

	S->WritePos += Length; 

	S->LastTSC = rdtsc();

	// total TCP bytes output
	s_TotalByte += Length;
	s_TotalPkt	+= 1;

	fProfile_Stop(12);
}

//---------------------------------------------------------------------------------------------

void fTCPStream_PacketAdd(TCPStream_t* S, u64 TS, TCPHeader_t* TCP, u32 Length, u8* Payload)
{
	//printf("tcp len: %i %08x %08x\n", Length, swap32(TCP->SeqNo), swap32(TCP->AckNo));
	u32 WindowSize 	= swap16( TCP->Window) * S->WindowScale;
	u32 SeqNo 		= swap32( TCP->SeqNo );
	u32 AckNo 		= swap32( TCP->AckNo );

	// last packet TS	
	S->LastTS 		= TS; 

	u32 Flag 		= StreamTCPFlag(TCP->Flags); 
	if (TCP_FLAG_SYN(TCP->Flags))
	{
		if (g_Verbose) printf("[%s] [%s] got syn\n", FormatTS(TS), S->Path);
		S->SeqNo = SeqNo + 1;

		fProfile_Start(9, "TCP PktAdd release");

		// release all reassembly buffer data . assumption is this is now a new tcp stream
		for (int i=0; i < S->BufferListPos; i++)
		{
			TCPBuffer_t* Buffer = S->BufferList[i];

			free(Buffer->Payload);
			Buffer->Payload = NULL;

			free(Buffer);

			s_TCPBufferMemoryTotal  -= sizeof(TCPBuffer_t) + Length;
			s_TCPBufferPacketTotal 	-= 1;
		}
		S->BufferListPos = 0;

		fProfile_Stop(9);

		// parse options
		u32 OLen = (4*swap16(TCP->Flags) >> 12) - 20;
		u8* Option = (u8*)(TCP + 1);
		for (int o=0; o < OLen; o++)
		{
			// end of options
			if (Option[o] == 0) break;

			// nop
			if (Option[o] == 1) continue;

			// MSS
			if ((Option[o+0] == 2) && (Option[o+1] == 4))
			{
				u32 MSS = ((u32)Option[o+2]<< 8) | (u32)Option[o+3];
				if (g_Verbose) printf("TCP MSS: %i\n", MSS);
				o+= 2;
			}
			// Window Scale 
			if ((Option[o+0] == 3) && (Option[o+1] == 3))
			{
				u32 Scale = Option[o+2];
				if (g_Verbose) printf("TCP WindowScale: %i\n", Scale);
				o+= 1;
				S->WindowScale = Scale;
			}
			// Selective Ack 
			if ((Option[o+0] == 4) && (Option[o+1] == 2))
			{
				if (g_Verbose) printf("TCP SelAck\n");
			}
			//printf("tcp offset: [%4i] %02x\n", o, Option[o]);
		}

		// indicate stream reset
		if (g_EnableTCPHeader)
		{
			TCPOutputHeader_t Header;
			Header.TS 		= TS;
			Header.Length 	= 0;
			Header.StreamID	= S->FlowID;
			Header.SeqNo	= 0; 
			Header.AckNo	= 0; 
			Header.Window	= 0; 
			Header.Flag		= Flag | TCPHEADER_FLAG_RESET; 
			Header.CRC		= 0;
			Header.CRC		+= Header.TS;
			Header.CRC		+= Header.Length;
			Header.CRC		+= Header.StreamID;
			Header.CRC		+= Header.SeqNo;
			Header.CRC		+= Header.AckNo;
			Header.CRC		+= Header.Window;
			Header.CRC		+= Header.Flag;

			fTCPStream_OutputHeader(S, &Header);
		}
	}

	if (Length == 0)
	{
		// usuall ack with no payload	
		if (g_EnableTCPHeader)
		{
			TCPOutputHeader_t Header;
			Header.TS 		= TS;
			Header.Length 	= Length;
			Header.StreamID	= S->FlowID;
			Header.SeqNo	= SeqNo; 
			Header.AckNo	= AckNo; 
			Header.Window	= WindowSize; 
			Header.Flag		= Flag; 
			Header.CRC		= 0;
			Header.CRC		+= Header.TS;
			Header.CRC		+= Header.Length;
			Header.CRC		+= Header.StreamID;
			Header.CRC		+= Header.SeqNo;
			Header.CRC		+= Header.AckNo;
			Header.CRC		+= Header.Window;
			Header.CRC		+= Header.Flag;

			fTCPStream_OutputHeader(S, &Header);
		}
	}
	else
	{
		s32 dSeqNo = SeqNo - S->SeqNo;
		if (dSeqNo == 0)
		{
			fTCPStream_OutputPayload(S, TS, Length, Payload, Flag, SeqNo, AckNo, WindowSize);
			if (S->BufferListPos > 0)
			{
				if (g_Verbose) printf("[%s] [%s] resend hit Seq:%08x : %i\n", FormatTS(TS), S->Path, SeqNo, S->BufferListPos);

				// check for reassembly
				fProfile_Start(11, "TCP PktAdd Reassembly");
				while (true)
				{
					bool Hit = false;
					for (int i=0; i < S->BufferListPos; i++)
					{
						TCPBuffer_t* Buffer = S->BufferList[i];
						if (Buffer->SeqNo == S->SeqNo)
						{
							if (g_Verbose) printf("[%s] [%s] reassembly hit Seq:%08x:%08x : %i %i\n", FormatTS(Buffer->TS), S->Path, S->SeqNo, S->SeqNo + Buffer->Length, S->BufferListPos, Length);
							fTCPStream_OutputPayload(S, TS, Buffer->Length, Buffer->Payload, Flag | TCPHEADER_FLAG_REASSEMBLE, S->SeqNo, 0, 0);
							Hit = true;
						}
						// redundant packet
						else if (Buffer->SeqNo < S->SeqNo)
						{
							if (g_Verbose) printf("[%s] [%s] redundant packet hit Seq:%08x BufferSeq:%08x : %i\n", FormatTS(Buffer->TS), S->Path, S->SeqNo, Buffer->SeqNo, S->BufferListPos);
							Hit = true;
						}

						// free and remove buffer 

						if (Hit)
						{
							free(Buffer->Payload);
							Buffer->Payload = NULL;	
							free(Buffer);

							s_TCPBufferMemoryTotal -= sizeof(TCPBuffer_t);

							for (int j=i; j < S->BufferListPos; j++)
							{
								S->BufferList[j] = S->BufferList[j+1];
							}
							S->BufferListPos--;
							break;
						}
					}
					if (!Hit) break;
				}
				fProfile_Stop(11);
			}
			// output stream data
		}
		else
		{

			fProfile_Start(7, "TCP PktAdd OOO");

			// reassembly packet thats not aligned but close to the current seq no
			s32 dRemain = (SeqNo + Length) - S->SeqNo;
			if ((SeqNo < S->SeqNo) && (dRemain > 0) && (dRemain < 1500))
			{
				if (g_Verbose) 
				{
					printf("[%s] [%s] unaligned seq resend: %i [%llx:%llx]\n",
						FormatTS(TS),
						S->Path,
						dRemain,
						S->WritePos,
						S->WritePos + dRemain
					   );
				}

				s32 PayloadOffset = S->SeqNo - SeqNo; 
				assert(PayloadOffset > 0);

				fTCPStream_OutputPayload(S, TS, dRemain, Payload + PayloadOffset, Flag | TCPHEADER_FLAG_REASSEMBLE, S->SeqNo, 0, 0);
			}
			// stop processing if too many gaps 
			else if (S->BufferListPos < S->BufferListMax)
			{
				TCPBuffer_t* B = (TCPBuffer_t*)malloc( sizeof(TCPBuffer_t) );
				assert(B != NULL);

				s_TCPBufferMemoryTotal  += sizeof(TCPBuffer_t) + Length;
				s_TCPBufferPacketTotal 	+= 1;
				g_TotalMemory 			+= sizeof(TCPBuffer_t) + Length;
				g_TotalMemoryTCP 		+= sizeof(TCPBuffer_t) + Length;

				memset(B, 0, sizeof(TCPBuffer_t));
				assert(Length < MAX_TCPSEGMENT);

				B->TS 		= TS;
				B->SeqNo 	= SeqNo;
				B->Length 	= Length;
				B->Payload	= malloc( Length );

				assert(B->Payload != NULL);
				memcpy(B->Payload, Payload, Length);

				S->BufferList[ S->BufferListPos++ ] = B;	

				if (g_Verbose)
				{
					printf("[%s] [%s] tcp gap Seq:%08x PktSeq:%08x delta %i OOPkts:%i SEnd:%08x\n", 
						FormatTS(TS), 
						S->Path, 
						S->SeqNo, 
						SeqNo, 
						dSeqNo,
						S->BufferListPos,
						SeqNo + Length);
					printf("[%s] TCP Buffer: %lliMB %.fK Pkts\n", FormatTS(TS), s_TCPBufferMemoryTotal / kMB(1), s_TCPBufferPacketTotal / 1e3 ); 
				}

				// special case when capture begins mid-stream
				if (S->SeqNo == 0)
				{
					if (g_Verbose) printf("[%s] %s midstream start Len:%i\n", FormatTS(TS), S->Path, Length); 
					S->SeqNo = swap32(TCP->SeqNo) + Length;
				}
			}
			fProfile_Stop(7);
		}
	}
}

//---------------------------------------------------------------------------------------------
// dump tcp stream export stats
void fTCPStream_Dump(u64 TS)
{
	static u64 LastStreamCnt = 0;

	fprintf(stderr, "TCPStream:\n");
	fprintf(stderr, "  TotalPkts     : %16lli\n", s_TotalPkt);
	fprintf(stderr, "  TotalByte     : %16lli\n", s_TotalByte);

	fprintf(stderr, "  OOO Packets   : %16lli\n", s_TCPBufferPacketTotal);

	s64 NewStreamCnt = s_StreamCnt - LastStreamCnt;
	fprintf(stderr, "  StreamCnt     : %16lli\n", s_StreamCnt);
	fprintf(stderr, "  StreamNew     : %16lli\n", NewStreamCnt);

	LastStreamCnt = s_StreamCnt;

	u32 StreamCnt 		= 0;
	u32 StreamInactive 	= 0;
	u32 StreamClose 	= 0;
	u64 TSC				= rdtsc();

	u32 Histo[1024];
	memset(Histo, 0, sizeof(Histo) );

	// garbage collect old streams
	for (int i=0; i < s_StreamCnt; i++)
	{
		TCPStream_t* S = s_Stream[i];
		assert(S != NULL);

		StreamCnt++;

		// stream is inactive
		if (!S->File)
		{
			StreamInactive++;
			continue;
		}

		u32 Index = S->WritePos / (16*1024);
		if (Index > 1023) Index = 1023;
		Histo[Index]++;

		// candidate for closing
		// no activity in the last 5 min 
		s64 dTS = TS - S->LastTS; 
		if (dTS > 60e9 * 5)
		{
			fProfile_Start(14, "TCP IO Close");
			fFile_Close(S->File);
			fProfile_Stop(14);

			S->File = NULL;

			// release 


			StreamClose++;
		}
	}

	for (int i=0; i < 1024; i++)
	{
		if (Histo[i] == 0) continue;
		printf("%8i : %8i\n", i*16*1024, Histo[i]);
	}

	fprintf(stderr, "  StreamFound   : %16i\n", StreamCnt);
	fprintf(stderr, "  StreamInactive: %16i (%.3f)\n", StreamInactive, StreamInactive / (float)StreamCnt);
	fprintf(stderr, "  StreamActive  : %16i\n", StreamCnt - StreamInactive - StreamClose);
	fprintf(stderr, "  StreamClose   : %16i\n", StreamClose); 
}
