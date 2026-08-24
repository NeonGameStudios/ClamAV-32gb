/* Bcj2.c -- Converter for x86 code (BCJ2)
2008-10-04 : Igor Pavlov : Public domain */

#include "Bcj2.h"
#include "7zAlloc.h"

#include <string.h>

#ifdef _LZMA_PROB32
#define CProb UInt32
#else
#define CProb UInt16
#endif

#define IsJcc(b0, b1) ((b0) == 0x0F && ((b1) & 0xF0) == 0x80)
#define IsJ(b0, b1) ((b1 & 0xFE) == 0xE8 || IsJcc(b0, b1))

#define kNumTopBits 24
#define kTopValue ((UInt32)1 << kNumTopBits)

#define kNumBitModelTotalBits 11
#define kBitModelTotal (1 << kNumBitModelTotalBits)
#define kNumMoveBits 5

#define RC_READ_BYTE (*buffer++)
#define RC_TEST { if (buffer == bufferLim) return SZ_ERROR_DATA; }
#define RC_INIT2 code = 0; range = 0xFFFFFFFF; \
  { int i; for (i = 0; i < 5; i++) { RC_TEST; code = (code << 8) | RC_READ_BYTE; }}

#define NORMALIZE if (range < kTopValue) { RC_TEST; range <<= 8; code = (code << 8) | RC_READ_BYTE; }

#define IF_BIT_0(p) ttt = *(p); bound = (range >> kNumBitModelTotalBits) * ttt; if (code < bound)
#define UPDATE_0(p) range = bound; *(p) = (CProb)(ttt + ((kBitModelTotal - ttt) >> kNumMoveBits)); NORMALIZE;
#define UPDATE_1(p) range -= bound; code -= bound; *(p) = (CProb)(ttt - (ttt >> kNumMoveBits)); NORMALIZE;

int Bcj2_Decode(
    const Byte *buf0, SizeT size0,
    const Byte *buf1, SizeT size1,
    const Byte *buf2, SizeT size2,
    const Byte *buf3, SizeT size3,
    Byte *outBuf, SizeT outSize)
{
  CProb p[256 + 2];
  SizeT inPos = 0, outPos = 0;

  const Byte *buffer, *bufferLim;
  UInt32 range, code;
  Byte prevByte = 0;

  unsigned int i;
  for (i = 0; i < sizeof(p) / sizeof(p[0]); i++)
    p[i] = kBitModelTotal >> 1;

  buffer = buf3;
  bufferLim = buffer + size3;
  RC_INIT2

  if (outSize == 0)
    return SZ_OK;

  for (;;)
  {
    Byte b;
    CProb *prob;
    UInt32 bound;
    UInt32 ttt;

    SizeT limit = size0 - inPos;
    if (outSize - outPos < limit)
      limit = outSize - outPos;
    while (limit != 0)
    {
      Byte b = buf0[inPos];
      outBuf[outPos++] = b;
      if (IsJ(prevByte, b))
        break;
      inPos++;
      prevByte = b;
      limit--;
    }

    if (limit == 0 || outPos == outSize)
      break;

    b = buf0[inPos++];

    if (b == 0xE8)
      prob = p + prevByte;
    else if (b == 0xE9)
      prob = p + 256;
    else
      prob = p + 257;

    IF_BIT_0(prob)
    {
      UPDATE_0(prob)
      prevByte = b;
    }
    else
    {
      UInt32 dest;
      const Byte *v;
      UPDATE_1(prob)
      if (b == 0xE8)
      {
        v = buf1;
        if (size1 < 4)
          return SZ_ERROR_DATA;
        buf1 += 4;
        size1 -= 4;
      }
      else
      {
        v = buf2;
        if (size2 < 4)
          return SZ_ERROR_DATA;
        buf2 += 4;
        size2 -= 4;
      }
      dest = (((UInt32)v[0] << 24) | ((UInt32)v[1] << 16) |
          ((UInt32)v[2] << 8) | ((UInt32)v[3])) - ((UInt32)outPos + 4);
      outBuf[outPos++] = (Byte)dest;
      if (outPos == outSize)
        break;
      outBuf[outPos++] = (Byte)(dest >> 8);
      if (outPos == outSize)
        break;
      outBuf[outPos++] = (Byte)(dest >> 16);
      if (outPos == outSize)
        break;
      outBuf[outPos++] = prevByte = (Byte)(dest >> 24);
    }
  }
  return (outPos == outSize) ? SZ_OK : SZ_ERROR_DATA;
}

#define BCJ2_STREAM_INPUT_SIZE 8192
#define BCJ2_STREAM_OUTPUT_SIZE 16384

typedef struct
{
  ISeqInStream *stream;
  UInt64 remaining;
  size_t pos;
  size_t size;
  Byte buffer[BCJ2_STREAM_INPUT_SIZE];
} CBcj2StreamInput;

typedef struct
{
  ISeqOutStream *stream;
  size_t size;
  Byte buffer[BCJ2_STREAM_OUTPUT_SIZE];
} CBcj2StreamOutput;

struct CBcj2MainOutStream
{
  ISeqOutStream s;
  CBcj2StreamInput inputs[4];
  CBcj2StreamOutput output;
  CProb probabilities[256 + 2];
  UInt64 mainSize;
  UInt64 mainPosition;
  UInt64 outSize;
  UInt64 outPosition;
  UInt32 range;
  UInt32 code;
  Byte prevByte;
  SRes status;
};

static SRes Bcj2StreamInput_ReadByte(CBcj2StreamInput *p, Byte *value)
{
  if (p == 0 || value == 0 || p->stream == 0)
    return SZ_ERROR_PARAM;
  if (p->pos == p->size)
  {
    size_t requested;
    SRes res;

    if (p->remaining == 0)
      return SZ_ERROR_DATA;
    requested = sizeof(p->buffer);
    if ((UInt64)requested > p->remaining)
      requested = (size_t)p->remaining;
    p->size = requested;
    res = p->stream->Read(p->stream, p->buffer, &p->size);
    if (res != SZ_OK)
      return res;
    if (p->size == 0 || p->size > requested)
      return SZ_ERROR_DATA;
    p->remaining -= (UInt64)p->size;
    p->pos = 0;
  }
  *value = p->buffer[p->pos++];
  return SZ_OK;
}

static SRes Bcj2StreamOutput_Flush(CBcj2StreamOutput *p)
{
  if (p == 0 || p->stream == 0)
    return SZ_ERROR_PARAM;
  if (p->size != 0)
  {
    if (p->stream->Write(p->stream, p->buffer, p->size) != p->size)
      return SZ_ERROR_WRITE;
    p->size = 0;
  }
  return SZ_OK;
}

static SRes Bcj2StreamOutput_WriteByte(CBcj2StreamOutput *p, Byte value)
{
  if (p == 0)
    return SZ_ERROR_PARAM;
  if (p->size == sizeof(p->buffer))
  {
    SRes res = Bcj2StreamOutput_Flush(p);
    if (res != SZ_OK)
      return res;
  }
  p->buffer[p->size++] = value;
  return SZ_OK;
}

static SRes Bcj2MainOutStream_SetError(CBcj2MainOutStream *p, SRes res)
{
  if (p != 0 && p->status == SZ_OK)
    p->status = res;
  return res;
}

static SRes Bcj2MainOutStream_ReadControlByte(CBcj2MainOutStream *p,
    Byte *value)
{
  SRes res = Bcj2StreamInput_ReadByte(&p->inputs[3], value);
  if (res != SZ_OK)
    return Bcj2MainOutStream_SetError(p, res);
  return SZ_OK;
}

static SRes Bcj2MainOutStream_ProcessByte(CBcj2MainOutStream *p,
    Byte instruction)
{
  CProb *probability;
  UInt32 bound;
  UInt32 probabilityValue;
  SRes res;

  res = Bcj2StreamOutput_WriteByte(&p->output, instruction);
  if (res != SZ_OK)
    return Bcj2MainOutStream_SetError(p, res);
  p->outPosition++;
  /* The compatibility decoder returns as soon as the requested output ends,
     even when the final byte is a branch opcode. Do not require side or range
     bytes that cannot contribute to the caller's bounded output. */
  if (p->outPosition == p->outSize)
    return SZ_OK;

  if (!IsJ(p->prevByte, instruction))
  {
    p->prevByte = instruction;
    return SZ_OK;
  }

  if (instruction == 0xE8)
    probability = p->probabilities + p->prevByte;
  else if (instruction == 0xE9)
    probability = p->probabilities + 256;
  else
    probability = p->probabilities + 257;

  probabilityValue = *probability;
  bound = (p->range >> kNumBitModelTotalBits) * probabilityValue;
  if (p->code < bound)
  {
    p->range = bound;
    *probability = (CProb)(probabilityValue +
        ((kBitModelTotal - probabilityValue) >> kNumMoveBits));
    if (p->range < kTopValue)
    {
      Byte value;
      res = Bcj2MainOutStream_ReadControlByte(p, &value);
      if (res != SZ_OK)
        return res;
      p->range <<= 8;
      p->code = (p->code << 8) | value;
    }
    p->prevByte = instruction;
  }
  else
  {
    Byte encoded[4];
    UInt32 destination;
    unsigned int i;
    unsigned int side = instruction == 0xE8 ? 1 : 2;

    p->range -= bound;
    p->code -= bound;
    *probability = (CProb)(probabilityValue -
        (probabilityValue >> kNumMoveBits));
    if (p->range < kTopValue)
    {
      Byte value;
      res = Bcj2MainOutStream_ReadControlByte(p, &value);
      if (res != SZ_OK)
        return res;
      p->range <<= 8;
      p->code = (p->code << 8) | value;
    }

    for (i = 0; i < 4; i++)
    {
      res = Bcj2StreamInput_ReadByte(&p->inputs[side], &encoded[i]);
      if (res != SZ_OK)
        return Bcj2MainOutStream_SetError(p, res);
    }
    destination = (((UInt32)encoded[0] << 24) |
                   ((UInt32)encoded[1] << 16) |
                   ((UInt32)encoded[2] << 8) |
                   (UInt32)encoded[3]) - ((UInt32)p->outPosition + 4);
    for (i = 0; i < 4 && p->outPosition < p->outSize; i++)
    {
      Byte value = (Byte)(destination >> (8 * i));
      res = Bcj2StreamOutput_WriteByte(&p->output, value);
      if (res != SZ_OK)
        return Bcj2MainOutStream_SetError(p, res);
      p->outPosition++;
      if (i == 3)
        p->prevByte = value;
    }
  }

  return SZ_OK;
}

static size_t Bcj2MainOutStream_Write(void *pp, const void *data, size_t size)
{
  CBcj2MainOutStream *p = (CBcj2MainOutStream *)pp;
  const Byte *bytes = (const Byte *)data;
  size_t i;

  if (p == 0 || (size != 0 && data == 0) || p->status != SZ_OK)
    return 0;
  if (p->mainPosition > p->mainSize ||
      (UInt64)size > p->mainSize - p->mainPosition)
  {
    Bcj2MainOutStream_SetError(p, SZ_ERROR_DATA);
    return 0;
  }

  for (i = 0; i < size; i++)
  {
    SRes res;

    p->mainPosition++;
    if (p->outPosition == p->outSize)
      continue;
    res = Bcj2MainOutStream_ProcessByte(p, bytes[i]);
    if (res != SZ_OK)
      return 0;
  }
  return size;
}

SRes Bcj2MainOutStream_Create(
    CBcj2MainOutStream **state,
    ISeqInStream *streams[4],
    const UInt64 sizes[4],
    UInt64 outSize,
    ISeqOutStream *outStream,
    ISzAlloc *alloc)
{
  CBcj2MainOutStream *p;
  unsigned int i;
  SRes res;

  if (state == 0 || streams == 0 || sizes == 0 || outStream == 0 ||
      alloc == 0 || streams[1] == 0 || streams[2] == 0 || streams[3] == 0)
    return SZ_ERROR_PARAM;
  *state = 0;
  p = (CBcj2MainOutStream *)IAlloc_Alloc(alloc, sizeof(*p));
  if (p == 0)
    return SZ_ERROR_MEM;
  memset(p, 0, sizeof(*p));
  p->s.Write = Bcj2MainOutStream_Write;
  p->output.stream = outStream;
  p->mainSize = sizes[0];
  p->outSize = outSize;
  p->range = 0xFFFFFFFF;
  p->status = SZ_OK;
  for (i = 1; i < 4; i++)
  {
    p->inputs[i].stream = streams[i];
    p->inputs[i].remaining = sizes[i];
  }
  for (i = 0; i < sizeof(p->probabilities) / sizeof(p->probabilities[0]); i++)
    p->probabilities[i] = kBitModelTotal >> 1;

  for (i = 0; i < 5; i++)
  {
    Byte value;
    res = Bcj2MainOutStream_ReadControlByte(p, &value);
    if (res != SZ_OK)
    {
      IAlloc_Free(alloc, p);
      return res;
    }
    p->code = (p->code << 8) | value;
  }

  *state = p;
  return SZ_OK;
}

ISeqOutStream *Bcj2MainOutStream_GetStream(CBcj2MainOutStream *state)
{
  return state == 0 ? 0 : &state->s;
}

SRes Bcj2MainOutStream_Finish(CBcj2MainOutStream *state)
{
  SRes res;

  if (state == 0)
    return SZ_ERROR_PARAM;
  if (state->status != SZ_OK)
    return state->status;
  if (state->mainPosition != state->mainSize ||
      state->outPosition != state->outSize)
    return Bcj2MainOutStream_SetError(state, SZ_ERROR_DATA);
  res = Bcj2StreamOutput_Flush(&state->output);
  if (res != SZ_OK)
    return Bcj2MainOutStream_SetError(state, res);
  return SZ_OK;
}

void Bcj2MainOutStream_Free(CBcj2MainOutStream *state, ISzAlloc *alloc)
{
  if (alloc != 0)
    IAlloc_Free(alloc, state);
}

SRes Bcj2_DecodeToStream(
    ISeqInStream *streams[4],
    const UInt64 sizes[4],
    UInt64 outSize,
    ISeqOutStream *outStream)
{
  Byte mainBuffer[BCJ2_STREAM_INPUT_SIZE];
  CBcj2MainOutStream *state = 0;
  UInt64 remaining;
  ISzAlloc alloc = { SzAlloc, SzFree };
  SRes res = SZ_OK;

  if (streams == 0 || sizes == 0 || outStream == 0 || streams[0] == 0)
    return SZ_ERROR_PARAM;
  res = Bcj2MainOutStream_Create(&state, streams, sizes, outSize,
      outStream, &alloc);
  if (res != SZ_OK)
    return res;
  remaining = sizes[0];
  while (remaining != 0)
  {
    size_t requested = sizeof(mainBuffer);
    size_t received;

    if ((UInt64)requested > remaining)
      requested = (size_t)remaining;
    received = requested;
    res = streams[0]->Read(streams[0], mainBuffer, &received);
    if (res != SZ_OK)
      break;
    if (received == 0 || received > requested)
    {
      res = SZ_ERROR_DATA;
      break;
    }
    if (Bcj2MainOutStream_GetStream(state)->Write(
            Bcj2MainOutStream_GetStream(state), mainBuffer, received) != received)
    {
      res = state->status == SZ_OK ? SZ_ERROR_WRITE : state->status;
      break;
    }
    remaining -= (UInt64)received;
  }
  if (res == SZ_OK)
    res = Bcj2MainOutStream_Finish(state);
  Bcj2MainOutStream_Free(state, &alloc);
  return res;
}
