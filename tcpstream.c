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

#include "fTypes.h"
#include "tcpstream.h"

//---------------------------------------------------------------------------------------------

typedef struct 
{
	u64			TS;
	u32			SeqNo;
	u32			Length;

	u8			Payload[8192];

} TCPBuffer_t;

typedef struct TCPStream_t 
{
	FILE*		Output;

	u32			SeqNo;					// current/next expected tcp seq number


	u32				BufferListPos;
	u32				BufferListMax;
	TCPBuffer_t*	BufferList[16*1024];

} TCPStream_t;

//---------------------------------------------------------------------------------------------

TCPStream_t* fTCPStream_Init(u64 MemorySize, char* OutputName)
{
	TCPStream_t* TCPStream = malloc( sizeof( TCPStream_t) );
	memset(TCPStream, 0, sizeof( TCPStream_t) );

	TCPStream->SeqNo = 0;
	TCPStream->BufferListPos = 0;
	TCPStream->BufferListMax = 16*1024;

	TCPStream->Output = fopen(OutputName, "w");
	if (!TCPStream->Output)
	{
		fprintf(stderr, "failed to create output file [%s]\n", OutputName);
		return NULL;
	}

	return TCPStream; 
}

//---------------------------------------------------------------------------------------------

void fTCPStream_Close(struct TCPStream_t* S)
{
	if(!S) return;

	fclose(S->Output);

	memset(S, 0, sizeof(TCPStream_t));
	free(S);
}

//---------------------------------------------------------------------------------------------
void fTCPStream_OutputPayload(TCPStream_t* S, u64 TS, u32 Length, u8* Payload)
{
	S->SeqNo += Length;
	fwrite(Payload, Length, 1, S->Output);
}

//---------------------------------------------------------------------------------------------

void fTCPStream_PacketAdd(TCPStream_t* S, u64 TS, TCPHeader_t* TCP, u32 Length, u8* Payload)
{
	if (TCP_FLAG_SYN(TCP->Flags))
	{
		fprintf(stderr, "got syn\n");
		S->SeqNo = swap32(TCP->SeqNo) + 1;
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
				fprintf(stderr, "[%s] resend hit Seq:%08x : %i\n", FormatTS(TS), SeqNo, S->BufferListPos);

				// check for reassembly
				while (true)
				{
					bool Hit = false;
					for (int i=0; i < S->BufferListPos; i++)
					{
						TCPBuffer_t* Buffer = S->BufferList[i];
						if (Buffer->SeqNo == S->SeqNo)
						{
							fprintf(stderr, "[%s] reassembly hit Seq:%08x : %i\n", FormatTS(Buffer->TS), S->SeqNo, S->BufferListPos);
							fTCPStream_OutputPayload(S, TS, Buffer->Length, Buffer->Payload);
							Hit = true;
						}
						// redundant packet
						else if (Buffer->SeqNo < S->SeqNo)
						{
							fprintf(stderr, "[%s] redundant packet hit Seq:%08x BufferSeq:%08x : %i\n", FormatTS(Buffer->TS), S->SeqNo, Buffer->SeqNo, S->BufferListPos);
							Hit = true;
						}

						// free and remove buffer 

						if (Hit)
						{
							free(Buffer);

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
			TCPBuffer_t* B = (TCPBuffer_t*)malloc( sizeof(TCPBuffer_t) );
			memset(B, 0, sizeof(TCPBuffer_t));

			B->TS 		= TS;
			B->SeqNo 	= SeqNo;
			B->Length 	= Length;
			memcpy(B->Payload, Payload, Length);

			S->BufferList[ S->BufferListPos++ ] = B;	
			assert(S->BufferListPos < S->BufferListMax);
			
			fprintf(stderr, "[%s] tcp gap Seq:%08x PktSeq:%08x delta %i\n", FormatTS(TS), S->SeqNo, SeqNo, dSeqNo);
		}
	}
}
