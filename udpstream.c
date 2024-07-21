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

extern bool			g_EnableUDPHeader;
extern bool			g_OutputPCAP;	

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

	// append .pcap
	u8 FilenamePCAP[2048];
	if (g_OutputPCAP)
	{
		sprintf(FilenamePCAP, "%s.pcap", FileName);
		FileName = FilenamePCAP;
	}

	Stream->F = fFile_Open(FileName, "w");
	if (!Stream->F)
	{
		fprintf(stderr, "failed to create file [%s]\n", Stream->FileName);
		return 0;
	}
	Stream->FlowID = FlowID;
	printf("[%s] FlowID:%i UDP Stream: [%s]\n", FormatTS(TS), FlowID, FileName);

	// if PCAP then write pcap header
	if (g_OutputPCAP)
	{
		PCAPHeader_t Header;
		Header.Magic 	= PCAPHEADER_MAGIC_NANO;
		Header.Major 	= PCAPHEADER_MAJOR;
		Header.Minor 	= PCAPHEADER_MINOR;
		Header.TimeZone = 0;
		Header.SigFlag 	= 0;
		Header.SnapLen 	= 0;
		Header.Link		= PCAPHEADER_LINK_ETHERNET;

		fFile_Write(Stream->F, &Header, sizeof(Header), true);
	}

	return Stream;
}

//---------------------------------------------------------------------------------------------

void fUDPStream_Add(UDPStream_t* Stream, u64 TS, PCAPPacket_t* Pkt, UDPHeader_t* UDPHeader)
{
	// output in PCAP format
	if (g_OutputPCAP)
	{
		fFile_Write(Stream->F, Pkt, sizeof(PCAPPacket_t) + Pkt->LengthCapture, true);
		return;
	}

	// write only the UDP payload
	u32 Length = swap16(UDPHeader->Length);	
	if (Length >= 16*1024)
	{
		fprintf(stderr, "udp packet length invalid UDP Length:%i PacketLength:%i\n", Length, Pkt->Length);
		return;
	}

	// ensure its caped at the packet length
	if (Length > Pkt->Length)
	{
		fprintf(stderr, "udp packet length truncated: Header %i Capture %i\n", Length, Pkt->Length);
		Length = Pkt->Length;
	}	

	if (g_EnableUDPHeader)
	{
		OutputHeader_t Header;
		Header.TS 		= TS;
		Header.Length 	= sizeof(UDPHeader_t) + Length; 
		Header.StreamID	= Stream->FlowID;
		fFile_Write(Stream->F, &Header, sizeof(Header), false );
	}

	// write the UDP header + payload 
	fFile_Write(Stream->F, UDPHeader, sizeof(UDPHeader_t) + Length, true);
}
