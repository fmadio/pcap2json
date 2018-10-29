#ifndef _PCAP2JSON_OUTPUT_H__
#define _PCAP2JSON_OUTPUT_H__

struct Output_t;

struct Output_t* 	Output_Create		(bool IsSTDOUT, bool IsESOut, u8* ESHostName, u32 ESHostPort, bool IsCompress);
void 				Output_LineAdd		(struct Output_t* Out, u8* Buffer, u32 BufferLen);
void 				Output_Close		(struct Output_t* Out);
u64 				Output_TotalByteSent(struct Output_t* Out);
u64 				Output_TotalLine	(struct Output_t* Out);

#endif
