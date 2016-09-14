#ifndef __FLOW_UDPSTREAM_H__
#define __FLOW_UDPSTREAM_H__

struct UDPStream_t;


struct UDPStream_t* 	fUDPStream_Init(char* OutputName, u32 FlowID, u64 TS);
void 					fUDPStream_Add(struct UDPStream_t* S, u64 TS, PCAPPacket_t* Pkt);
#endif
