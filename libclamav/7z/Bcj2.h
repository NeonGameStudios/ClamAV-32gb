/* Bcj2.h -- Converter for x86 code (BCJ2)
2009-02-07 : Igor Pavlov : Public domain */

#ifndef __BCJ2_H
#define __BCJ2_H

#include "Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
Conditions:
  outSize <= FullOutputSize,
  where FullOutputSize is full size of output stream of x86_2 filter.

If buf0 overlaps outBuf, there are two required conditions:
  1) (buf0 >= outBuf)
  2) (buf0 + size0 >= outBuf + FullOutputSize).

Returns:
  SZ_OK
  SZ_ERROR_DATA - Data error
*/

int Bcj2_Decode(
    const Byte *buf0, SizeT size0,
    const Byte *buf1, SizeT size1,
    const Byte *buf2, SizeT size2,
    const Byte *buf3, SizeT size3,
    Byte *outBuf, SizeT outSize);

/* Decode BCJ2 from four sequential inputs without retaining the complete
   decoded folder. Each input is bounded by its declared size and output is
   forwarded in fixed windows. */
SRes Bcj2_DecodeToStream(
    ISeqInStream *streams[4],
    const UInt64 sizes[4],
    UInt64 outSize,
    ISeqOutStream *outStream);

typedef struct CBcj2MainOutStream CBcj2MainOutStream;

/* Create a resumable BCJ2 merger. Logical streams 1 (CALL), 2 (JUMP), and
   3 (range control) are read sequentially from bounded inputs. Decoded MAIN
   bytes are then supplied through Bcj2MainOutStream_GetStream(). */
SRes Bcj2MainOutStream_Create(
    CBcj2MainOutStream **state,
    ISeqInStream *streams[4],
    const UInt64 sizes[4],
    UInt64 outSize,
    ISeqOutStream *outStream,
    ISzAlloc *alloc);

ISeqOutStream *Bcj2MainOutStream_GetStream(CBcj2MainOutStream *state);
SRes Bcj2MainOutStream_Finish(CBcj2MainOutStream *state);
void Bcj2MainOutStream_Free(CBcj2MainOutStream *state, ISzAlloc *alloc);

#ifdef __cplusplus
}
#endif

#endif
