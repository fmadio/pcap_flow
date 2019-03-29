#ifndef __FILE_FMAD_H__
#define __FILE_FMAD_H__

struct fFile_t;

struct fFile_t* fFile_Open		(u8* Path, u8* Mode);
void 			fFile_Write		(struct fFile_t* F, void* Buffer, u32 Length, bool IsPayload);
void 			fFile_Close		(struct fFile_t* F);
void 			fFile_Flush		(struct fFile_t* F);

void 			fFile_SizeMin	(u32 SizeMin);

#endif
