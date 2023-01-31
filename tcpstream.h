#ifndef __FLOW_TCPSTREAM_H__
#define __FLOW_TCPSTREAM_H__

struct TCPStream_t;

void fTCPStream_MaxFlow				(u32 MaxFlow);
struct TCPStream_t* fTCPStream_Init	(u64 MemorySize, char* OutputName, u32 FlowID, u32 FlowHash, u64 TS);
void fTCPStream_PacketAdd			(struct TCPStream_t* S, u64 TS, TCPHeader_t* TCP, s32 PayloadLength, u8* Payload);
void fTCPStream_Close				(struct TCPStream_t* S);
void fTCPStream_Flush				(struct TCPStream_t* S);
void fTCPStream_Dump				(u64 TS);
void fTCPStream_FlowStats			(struct TCPStream_t* S, FILE* Out);

#endif
