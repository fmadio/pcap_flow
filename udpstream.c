//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
//
// udp stream exporter. kinda silly as UDP isnt really a stream. the utility of this
// is a single flow is extracted into a single file
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
#include "udpstream.h"

//---------------------------------------------------------------------------------------------

// public header output for each stream

typedef struct
{
	u64		TS;					// timestamp of last byte	
	u16		Length;				// number of bytes in this packet
	u16		StreamID;			// unique id per flow

} OutputHeader_t;

typedef struct UDPStream_t
{
	FILE*	F;					// output file handle
	char	FileName[256];		// file handle name
	u32		FlowID;				// master flowid for this stream

} UDPStream_t;

//---------------------------------------------------------------------------------------------

UDPStream_t* fUDPStream_Init(char* FileName, u32 FlowID, u64 TS)
{
	UDPStream_t* Stream = malloc(sizeof(UDPStream_t));
	memset(Stream, 0, sizeof(UDPStream_t));

	Stream->F = fopen(FileName, "w");
	if (!Stream->F)
	{
		fprintf(stderr, "failed to create file [%s]\n", Stream->FileName);
		return 0;
	}
	Stream->FlowID = FlowID;

	printf("[%s] FlowID:%i UDP Stream: [%s]\n", FormatTS(TS), FlowID, FileName);

	return Stream;
}

//---------------------------------------------------------------------------------------------

void fUDPStream_Add(UDPStream_t* Stream, u64 TS, PCAPPacket_t* Pkt)
{
	OutputHeader_t Header;
	Header.TS 		= TS;
	Header.Length 	= Pkt->LengthCapture;
	Header.StreamID	= Stream->FlowID;
	fwrite(&Header, sizeof(Header), 1, Stream->F);

	fwrite(Pkt+1, Pkt->LengthCapture, 1, Stream->F);
}
