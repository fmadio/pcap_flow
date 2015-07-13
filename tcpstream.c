//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015, fmad engineering llc 
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
#include "tcpstream.h"

//---------------------------------------------------------------------------------------------

#define MAX_TCPSEGMENT		(16*1024)
typedef struct 
{
	u64			TS;
	u32			SeqNo;
	u32			Length;

	u8*			Payload;

} TCPBuffer_t;

typedef struct TCPStream_t 
{
	int				fd;

	u32				SeqNo;					// current/next expected tcp seq number
	u32				FlowID;					// unique flow id in this pcap


	u32				BufferListPos;
	u32				BufferListMax;
	TCPBuffer_t*	BufferList[16*1024];

	char			Path[1024];				// full path 
	u64				LastTSC;				// cycle counter when this file was last accessed 

	bool			IsFileCreate;			// has the output file been created yet. e.g. for
											// file truncation

	u64				WritePos;				// number of bytes written to output (including stream headers)

} TCPStream_t;

// public header output for each stream

typedef struct
{
	u64		TS;					// timestamp of last byte	
	u16		Length;				// number of bytes in this packet
	u16		StreamID;			// unique id per flow

} TCPOutputHeader_t;

//---------------------------------------------------------------------------------------------

static int			s_StreamCnt		= 0;
static int			s_StreamMax		= 1024*1024;
static TCPStream_t* s_Stream[1024*1024];

// easy to run into maximum open file handles, thus only keep a small cache of open files 

static bool			s_StreamCacheInit 		= false;			// init on first creation
static u32			s_StreamCacheMax 		= 32*1024;			// NOTE: large number here requires
																//       linux ulimit number to also be high 
static TCPStream_t* s_StreamCache[32*1024];

extern bool			g_EnableTCPHeader;

static u64			s_TCPBufferMemoryTotal	= 0;				// total amount of gapped tcp data
static u64			s_TCPBufferPacketTotal	= 0;				// total number of packets unclaimed

//---------------------------------------------------------------------------------------------

TCPStream_t* fTCPStream_Init(u64 MemorySize, char* OutputName, u32 FlowID)
{
	TCPStream_t* TCPStream = malloc( sizeof( TCPStream_t) );
	assert(TCPStream != NULL);
	memset(TCPStream, 0, sizeof( TCPStream_t) );

	TCPStream->SeqNo = 0;
	TCPStream->BufferListPos = 0;
	TCPStream->BufferListMax = 16*1024;

	strncpy(TCPStream->Path, OutputName, sizeof(TCPStream->Path));
	TCPStream->fd = -1; 

	TCPStream->FlowID 		= FlowID;

	TCPStream->IsFileCreate	= false;

	// init cache
	if (!s_StreamCacheInit)
	{
		s_StreamCacheInit = true;
		memset(s_StreamCache, 0, sizeof(void *) * s_StreamCacheMax);
	}
	return TCPStream; 
}

//---------------------------------------------------------------------------------------------

static void fTCPStream_Open(TCPStream_t* S)
{
	// find oldest entry in the cache
	u32 Index = 0;
	u64 IndexTSC = 0; 

	for (int i=0; i < s_StreamCacheMax; i++)
	{
		// empty slot, so use it
		if (!s_StreamCache[i])
		{
			Index = i;
			break;
		}

		// found older entry 
		if (s_StreamCache[i]->LastTSC < IndexTSC)
		{
			Index 	 = i;
			IndexTSC = s_StreamCache[i]->LastTSC;
		}
	}

	// close eviected stream
	if (s_StreamCache[ Index ])
	{
		close(s_StreamCache[Index]->fd);
		s_StreamCache[Index]->fd = -1;
	}
	//printf("[%s] open file\n", S->Path);

	// open and create entry 
	int Flags = O_CREAT | O_RDWR;
	Flags |= (!S->IsFileCreate) ? O_TRUNC : 0;

	S->fd = open64(S->Path, Flags, S_IRWXU);
	if (S->fd < 0)
	{
		fprintf(stderr, "failed to create output file [%s] errno:%i\n", S->Path, errno);
		exit(-1);
	}

	// assign to cache
	s_StreamCache[Index] = S;
}

//---------------------------------------------------------------------------------------------

void fTCPStream_Close(struct TCPStream_t* S)
{
	if(!S) return;

	close(S->fd);

	memset(S, 0, sizeof(TCPStream_t));
	free(S);
}

//---------------------------------------------------------------------------------------------
void fTCPStream_OutputPayload(TCPStream_t* S, u64 TS, u32 Length, u8* Payload)
{
	// is sthe fil open ? 
	if (S->fd <= 0)
	{
		// evict an old stream	
		fTCPStream_Open(S);	
		fprintf(stderr, "[%s] open file\n", FormatTS(TS));
	}
	S->SeqNo += Length;

	int rlen;
	if (g_EnableTCPHeader)
	{
		TCPOutputHeader_t Header;
		Header.TS 		= TS;
		Header.Length 	= Length;
		Header.StreamID	= S->FlowID;
		rlen = write(S->fd, &Header, sizeof(Header));
		S->WritePos += sizeof(Header);
	}
	rlen = write(S->fd, Payload, Length);
	S->WritePos += Length; 

	S->LastTSC = rdtsc();
}

//---------------------------------------------------------------------------------------------

void fTCPStream_PacketAdd(TCPStream_t* S, u64 TS, TCPHeader_t* TCP, u32 Length, u8* Payload)
{
	if (TCP_FLAG_SYN(TCP->Flags))
	{
		fprintf(stderr, "[%s] [%s] got syn\n", FormatTS(TS), S->Path);
		S->SeqNo = swap32(TCP->SeqNo) + 1;

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
	}
	if (Length == 0)
	{
		//printf("tcp pkt %i\n", Length);
	}
	else
	{
		u32 SeqNo = swap32( TCP->SeqNo );

		s32 dSeqNo = SeqNo - S->SeqNo;
		if (dSeqNo == 0)
		{
			fTCPStream_OutputPayload(S, TS, Length, Payload);

			if (S->BufferListPos > 0)
			{
				fprintf(stderr, "[%s] [%s] resend hit Seq:%08x : %i\n", FormatTS(TS), S->Path, SeqNo, S->BufferListPos);

				// check for reassembly
				while (true)
				{
					bool Hit = false;
					for (int i=0; i < S->BufferListPos; i++)
					{
						TCPBuffer_t* Buffer = S->BufferList[i];
						if (Buffer->SeqNo == S->SeqNo)
						{
							fprintf(stderr, "[%s] [%s] reassembly hit Seq:%08x:%08x : %i\n", FormatTS(Buffer->TS), S->Path, S->SeqNo, S->SeqNo + Buffer->Length, S->BufferListPos, Length);
							fTCPStream_OutputPayload(S, TS, Buffer->Length, Buffer->Payload);
							Hit = true;
						}
						// redundant packet
						else if (Buffer->SeqNo < S->SeqNo)
						{
							fprintf(stderr, "[%s] [%s] redundant packet hit Seq:%08x BufferSeq:%08x : %i\n", FormatTS(Buffer->TS), S->Path, S->SeqNo, Buffer->SeqNo, S->BufferListPos);
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
			}
			// output stream data
		}
		else
		{
			// reassembly packet thats not aligned but close to the current seq no
			s32 dRemain = (SeqNo + Length) - S->SeqNo;
			if ((SeqNo < S->SeqNo) && (dRemain > 0) && (dRemain < 1500))
			{
				fprintf(stderr, "[%s] [%s] unaligned seq resend: %i [%llx:%llx]\n",
						FormatTS(TS),
						S->Path,
						dRemain,
						S->WritePos,
						S->WritePos + dRemain
					   );

				s32 PayloadOffset = S->SeqNo - SeqNo; 
				assert(PayloadOffset > 0);

				fTCPStream_OutputPayload(S, TS, dRemain, Payload + PayloadOffset);
			}
			// stop processing if too many gaps 
			else if (S->BufferListPos < S->BufferListMax)
			{
				TCPBuffer_t* B = (TCPBuffer_t*)malloc( sizeof(TCPBuffer_t) );
				assert(B != NULL);
				s_TCPBufferMemoryTotal  += sizeof(TCPBuffer_t) + Length;
				s_TCPBufferPacketTotal 	+= 1;

				memset(B, 0, sizeof(TCPBuffer_t));
				assert(Length < MAX_TCPSEGMENT);

				B->TS 		= TS;
				B->SeqNo 	= SeqNo;
				B->Length 	= Length;
				B->Payload	= malloc( Length );

				assert(B->Payload != NULL);
				memcpy(B->Payload, Payload, Length);

				S->BufferList[ S->BufferListPos++ ] = B;	

				fprintf(stderr, "[%s] [%s] tcp gap Seq:%08x PktSeq:%08x delta %i OOPkts:%i SEnd:%08x\n", 
						FormatTS(TS), 
						S->Path, 
						S->SeqNo, 
						SeqNo, 
						dSeqNo,
						S->BufferListPos,
						SeqNo + Length);
				fprintf(stderr, "[%s] TCP Buffer: %lliMB %.fK Pkts\n", FormatTS(TS), s_TCPBufferMemoryTotal / kMB(1), s_TCPBufferPacketTotal / 1e3 ); 

				// special case when capture begins mid-stream
				if (S->SeqNo == 0)
				{
					fprintf(stderr, "[%s] %s midstream start Len:%i\n", FormatTS(TS), S->Path, Length); 
					S->SeqNo = swap32(TCP->SeqNo) + Length;
				}	
			}
		}
	}
}
