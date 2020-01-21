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
#include "fFile.h"
#include "udpstream.h"

//---------------------------------------------------------------------------------------------

// public header output for each stream

typedef struct
{
	u64		TS;							// timestamp of last byte	
	u16		Length;						// number of bytes in this packet
	u16		StreamID;					// unique id per flow

} OutputHeader_t;

typedef struct UDPStream_t
{
	struct fFile_t*	F;					// output file handle
	char			FileName[1024];		// file handle name
	u32				FlowID;				// master flowid for this stream

} UDPStream_t;

//---------------------------------------------------------------------------------------------

UDPStream_t* fUDPStream_Init(char* FileName, u32 FlowID, u64 TS)
{
	UDPStream_t* Stream = malloc(sizeof(UDPStream_t));
	memset(Stream, 0, sizeof(UDPStream_t));

	Stream->F = fFile_Open(FileName, "w");
	if (!Stream->F)
	{
		fprintf(stderr, "failed to create file [%s]\n", Stream->FileName);
		return 0;
	}
	Stream->FlowID = FlowID;
	//printf("[%s] FlowID:%i UDP Stream: [%s]\n", FormatTS(TS), FlowID, FileName);

	return Stream;
}

//---------------------------------------------------------------------------------------------

void fUDPStream_Add(UDPStream_t* Stream, u64 TS, PCAPPacket_t* Pkt, UDPHeader_t* UDPHeader)
{
	u32 Length = swap16(UDPHeader->Length);	
	assert(Length < 16*1024);

	// ensure its caped at the packet length
	if (Length > Pkt->Length)
	{
		Length = Pkt->Length;
		fprintf(stderr, "udp packet length truncated: Header %i Capture %i\n", Length, Pkt->Length);
	}	

	OutputHeader_t Header;
	Header.TS 		= TS;
	Header.Length 	= sizeof(UDPHeader_t) + Length; 
	Header.StreamID	= Stream->FlowID;
	fFile_Write(Stream->F, &Header, sizeof(Header), false );

	// write the UDP header + payload 
	fFile_Write(Stream->F, UDPHeader, sizeof(UDPHeader_t) + Length, true);
}
