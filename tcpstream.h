#ifndef __FLOW_TCPSTREAM_H__
#define __FLOW_TCPSTREAM_H__

struct TCPStream_t;

struct TCPStream_t* fTCPStream_Init	(u64 MemorySize, char* OutputName, u32 FlowID, u64 TS);
void fTCPStream_PacketAdd			(struct TCPStream_t* S, u64 TS, TCPHeader_t* TCP, u32 PayloadLength, u8* Payload);
void fTCPStream_Close				(struct TCPStream_t* S);
void fTCPStream_Flush				(struct TCPStream_t* S);
void fTCPStream_Dump				(void);

#endif
