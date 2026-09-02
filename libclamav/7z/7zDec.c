/* 7zDec.c -- Decoding from 7z folder
2010-11-02 : Igor Pavlov : Public domain */

#include <string.h>

#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#endif

#define _7ZIP_PPMD_SUPPPORT

#include "7z.h"

#include "Bcj2.h"
#include "Bra.h"
#include "CpuArch.h"
#include "LzmaDec.h"
#include "Lzma2Dec.h"
#include "7zCrc.h"
#ifdef _7ZIP_PPMD_SUPPPORT
#include "Ppmd7.h"
#endif

#define k_Copy 0
#define k_LZMA2 0x21
#define k_LZMA  0x30101
#define k_BCJ   0x03030103
#define k_PPC   0x03030205
#define k_ARM   0x03030501
#define k_ARMT  0x03030701
#define k_SPARC 0x03030805
#define k_BCJ2  0x0303011B

#ifdef _7ZIP_PPMD_SUPPPORT

#define k_PPMD 0x30401

typedef struct
{
  IByteIn p;
  const Byte *cur;
  const Byte *end;
  const Byte *begin;
  UInt64 processed;
  UInt64 limit;
  Bool extra;
  SRes res;
  ILookInStream *inStream;
} CByteInToLook;

int SzPpmdInputAccountingAllowed(UInt64 processed, size_t buffered, UInt64 limit)
{
  UInt64 buffered64 = (UInt64)buffered;

  return (size_t)buffered64 == buffered &&
         processed <= limit &&
         buffered64 <= limit - processed;
}

int SzDecoderInputProgressAllowed(UInt64 remaining, size_t available, size_t consumed)
{
  UInt64 available64 = (UInt64)available;
  UInt64 consumed64 = (UInt64)consumed;

  return (size_t)available64 == available &&
         (size_t)consumed64 == consumed &&
         consumed64 <= available64 &&
         consumed64 <= remaining;
}

static Byte ReadByte(void *pp)
{
  CByteInToLook *p = (CByteInToLook *)pp;
  if (p->cur != p->end)
    return *p->cur++;
  if (p->res == SZ_OK)
  {
    size_t size = p->cur - p->begin;
    if (!SzPpmdInputAccountingAllowed(p->processed, size, p->limit)) {
      p->res = SZ_ERROR_DATA;
      p->extra = True;
      return 0;
    }
    p->processed += size;
    if (p->processed >= p->limit) {
      p->extra = True;
      return 0;
    }
    p->res = p->inStream->Skip(p->inStream, size);
    if (p->res != SZ_OK) {
      p->extra = True;
      return 0;
    }
    size = (1 << 25);
    if (size > p->limit - p->processed)
      size = (size_t)(p->limit - p->processed);
    p->res = p->inStream->Look(p->inStream, (const void **)&p->begin, &size);
    p->cur = p->begin;
    p->end = p->begin + size;
    if (size != 0)
      return *p->cur++;;
  }
  p->extra = True;
  return 0;
}

static SRes SzDecodePpmd(CSzCoderInfo *coder, UInt64 inSize, ILookInStream *inStream,
    Byte *outBuffer, SizeT outSize, ISzAlloc *allocMain)
{
  CPpmd7 ppmd;
  CByteInToLook s;
  SRes res = SZ_OK;

  s.p.Read = ReadByte;
  s.inStream = inStream;
  s.begin = s.end = s.cur = NULL;
  s.extra = False;
  s.res = SZ_OK;
  s.processed = 0;
  s.limit = inSize;

  if (coder->Props.size != 5)
    return SZ_ERROR_UNSUPPORTED;

  {
    unsigned order = coder->Props.data[0];
    UInt32 memSize = GetUi32(coder->Props.data + 1);
    if (order < PPMD7_MIN_ORDER ||
        order > PPMD7_MAX_ORDER ||
        memSize < PPMD7_MIN_MEM_SIZE ||
        memSize > PPMD7_MAX_MEM_SIZE)
      return SZ_ERROR_UNSUPPORTED;
    Ppmd7_Construct(&ppmd);
    if (!Ppmd7_Alloc(&ppmd, memSize, allocMain))
      return SZ_ERROR_MEM;
    Ppmd7_Init(&ppmd, order);
  }
  {
    CPpmd7z_RangeDec rc;
    Ppmd7z_RangeDec_CreateVTable(&rc);
    rc.Stream = &s.p;
    if (!Ppmd7z_RangeDec_Init(&rc))
      res = SZ_ERROR_DATA;
    else if (s.extra)
      res = (s.res != SZ_OK ? s.res : SZ_ERROR_DATA);
    else
    {
      SizeT i;
      for (i = 0; i < outSize; i++)
      {
        int sym = Ppmd7_DecodeSymbol(&ppmd, &rc.p);
        if (s.extra || sym < 0)
          break;
        outBuffer[i] = (Byte)sym;
      }
      if (i != outSize)
        res = (s.res != SZ_OK ? s.res : SZ_ERROR_DATA);
      else if (!SzPpmdInputAccountingAllowed(s.processed, s.cur - s.begin, inSize) ||
               s.processed + (UInt64)(s.cur - s.begin) != inSize ||
               !Ppmd7z_RangeDec_IsFinishedOK(&rc))
        res = SZ_ERROR_DATA;
    }
  }
  Ppmd7_Free(&ppmd, allocMain);
  return res;
}

#endif


static SRes SzDecodeLzma(CSzCoderInfo *coder, UInt64 inSize, ILookInStream *inStream,
    Byte *outBuffer, SizeT outSize, ISzAlloc *allocMain)
{
  CLzmaDec state;
  SRes res = SZ_OK;

  LzmaDec_Construct(&state);
  RINOK(LzmaDec_AllocateProbs(&state, coder->Props.data, (unsigned)coder->Props.size, allocMain));
  state.dic = outBuffer;
  state.dicBufSize = outSize;
  LzmaDec_Init(&state);

  for (;;)
  {
    Byte *inBuf = NULL;
    size_t lookahead = (1 << 18);
    if (lookahead > inSize)
      lookahead = (size_t)inSize;
    res = inStream->Look((void *)inStream, (const void **)&inBuf, &lookahead);
    if (res != SZ_OK)
      break;

    {
      SizeT inProcessed = (SizeT)lookahead, dicPos = state.dicPos;
      ELzmaStatus status;
      res = LzmaDec_DecodeToDic(&state, outSize, inBuf, &inProcessed, LZMA_FINISH_END, &status);
      if (!SzDecoderInputProgressAllowed(inSize, lookahead, (size_t)inProcessed)) {
        res = SZ_ERROR_DATA;
        break;
      }
      lookahead -= inProcessed;
      inSize -= inProcessed;
      if (res != SZ_OK)
        break;
      if (state.dicPos == state.dicBufSize || (inProcessed == 0 && dicPos == state.dicPos))
      {
        if (state.dicBufSize != outSize || lookahead != 0 ||
            (status != LZMA_STATUS_FINISHED_WITH_MARK &&
             status != LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK))
          res = SZ_ERROR_DATA;
        break;
      }
      res = inStream->Skip((void *)inStream, inProcessed);
      if (res != SZ_OK)
        break;
    }
  }

  LzmaDec_FreeProbs(&state, allocMain);
  return res;
}

static SRes SzDecodeLzma2(CSzCoderInfo *coder, UInt64 inSize, ILookInStream *inStream,
    Byte *outBuffer, SizeT outSize, ISzAlloc *allocMain)
{
  CLzma2Dec state;
  SRes res = SZ_OK;

  Lzma2Dec_Construct(&state);
  if (coder->Props.size != 1)
    return SZ_ERROR_DATA;
  RINOK(Lzma2Dec_AllocateProbs(&state, coder->Props.data[0], allocMain));
  state.decoder.dic = outBuffer;
  state.decoder.dicBufSize = outSize;
  Lzma2Dec_Init(&state);

  for (;;)
  {
    Byte *inBuf = NULL;
    size_t lookahead = (1 << 18);
    if (lookahead > inSize)
      lookahead = (size_t)inSize;
    res = inStream->Look((void *)inStream, (const void **)&inBuf, &lookahead);
    if (res != SZ_OK)
      break;

    {
      SizeT inProcessed = (SizeT)lookahead, dicPos = state.decoder.dicPos;
      ELzmaStatus status;
      res = Lzma2Dec_DecodeToDic(&state, outSize, inBuf, &inProcessed, LZMA_FINISH_END, &status);
      if (!SzDecoderInputProgressAllowed(inSize, lookahead, (size_t)inProcessed)) {
        res = SZ_ERROR_DATA;
        break;
      }
      lookahead -= inProcessed;
      inSize -= inProcessed;
      if (res != SZ_OK)
        break;
      if (state.decoder.dicPos == state.decoder.dicBufSize || (inProcessed == 0 && dicPos == state.decoder.dicPos))
      {
        if (state.decoder.dicBufSize != outSize || lookahead != 0 ||
            (status != LZMA_STATUS_FINISHED_WITH_MARK))
          res = SZ_ERROR_DATA;
        break;
      }
      res = inStream->Skip((void *)inStream, inProcessed);
      if (res != SZ_OK)
        break;
    }
  }

  Lzma2Dec_FreeProbs(&state, allocMain);
  return res;
}

static SRes SzDecodeCopy(UInt64 inSize, ILookInStream *inStream, Byte *outBuffer)
{
  while (inSize > 0)
  {
    void *inBuf;
    size_t curSize = (1 << 18);
    if (curSize > inSize)
      curSize = (size_t)inSize;
    RINOK(inStream->Look((void *)inStream, (const void **)&inBuf, &curSize));
    if (curSize == 0)
      return SZ_ERROR_INPUT_EOF;
    memcpy(outBuffer, inBuf, curSize);
    outBuffer += curSize;
    inSize -= curSize;
    RINOK(inStream->Skip((void *)inStream, curSize));
  }
  return SZ_OK;
}

static SRes SzStreamWrite(ISeqOutStream *outStream, const Byte *data, size_t size)
{
  if (!size)
    return SZ_OK;
  return outStream->Write(outStream, data, size) == size ? SZ_OK : SZ_ERROR_WRITE;
}

/* Bound decompressor work between output/progress callbacks. The dictionary
   remains fully allocated for codec semantics, but no decode step may produce
   more than this window before the caller can enforce its deadline. */
#define SZ_DECODE_OUTPUT_WINDOW_SIZE (1 << 18)

static SRes SzDecodeCopyToStream(UInt64 inSize, ILookInStream *inStream, ISeqOutStream *outStream)
{
  while (inSize > 0) {
    const void *inBuf;
    size_t curSize = (1 << 18);
    if (curSize > inSize)
      curSize = (size_t)inSize;
    RINOK(inStream->Look((void *)inStream, &inBuf, &curSize));
    if (!curSize)
      return SZ_ERROR_INPUT_EOF;
    RINOK(SzStreamWrite(outStream, (const Byte *)inBuf, curSize));
    inSize -= curSize;
    RINOK(inStream->Skip((void *)inStream, curSize));
  }
  return SZ_OK;
}

static SRes SzDecodeLzmaToStream(const CSzCoderInfo *coder, UInt64 inSize, UInt64 outSize,
    ILookInStream *inStream, ISeqOutStream *outStream, ISzAlloc *allocMain)
{
  CLzmaDec state;
  Byte *dict = NULL;
  UInt64 remaining = outSize;
  SRes res;

  if (outSize == 0)
    return SZ_OK;
  LzmaDec_Construct(&state);
  RINOK(LzmaDec_AllocateProbs(&state, coder->Props.data, (unsigned)coder->Props.size, allocMain));
  if (outSize < state.prop.dicSize)
    state.prop.dicSize = (UInt32)outSize;
  if (state.prop.dicSize != 0) {
    dict = (Byte *)IAlloc_Alloc(allocMain, state.prop.dicSize);
    if (!dict) {
      LzmaDec_FreeProbs(&state, allocMain);
      return SZ_ERROR_MEM;
    }
  }
  state.dic        = dict;
  state.dicBufSize = state.prop.dicSize;
  LzmaDec_Init(&state);

  while (remaining > 0) {
    const void *inBuf;
    size_t lookahead = (1 << 18);
    size_t oldPos, inProcessed;
    SizeT dicLimit, outputWindow, produced;
    ELzmaStatus status;
    ELzmaFinishMode finishMode;

    if (lookahead > inSize)
      lookahead = (size_t)inSize;
    if (!lookahead) {
      res = SZ_ERROR_INPUT_EOF;
      goto done;
    }
    res = inStream->Look((void *)inStream, &inBuf, &lookahead);
    if (res != SZ_OK)
      goto done;
    if (!lookahead) {
      res = SZ_ERROR_INPUT_EOF;
      goto done;
    }
    oldPos = state.dicPos;
    outputWindow = state.dicBufSize - state.dicPos;
    if (outputWindow > SZ_DECODE_OUTPUT_WINDOW_SIZE)
      outputWindow = SZ_DECODE_OUTPUT_WINDOW_SIZE;
    if ((UInt64)outputWindow > remaining)
      outputWindow = (SizeT)remaining;
    if (outputWindow == 0) {
      res = SZ_ERROR_DATA;
      goto done;
    }
    dicLimit = state.dicPos + outputWindow;
    finishMode = remaining <= outputWindow ? LZMA_FINISH_END : LZMA_FINISH_ANY;
    inProcessed = lookahead;
    res = LzmaDec_DecodeToDic(&state, dicLimit, (const Byte *)inBuf,
                              &inProcessed, finishMode, &status);
    if (!SzDecoderInputProgressAllowed(inSize, lookahead, inProcessed)) {
      res = SZ_ERROR_DATA;
      goto done;
    }
    if (inProcessed) {
      res = inStream->Skip((void *)inStream, inProcessed);
      if (res != SZ_OK)
        goto done;
    }
    inSize -= inProcessed;
    if (state.dicPos < oldPos)
      res = SZ_ERROR_DATA;
    produced = state.dicPos - oldPos;
    if ((UInt64)produced > remaining)
      res = SZ_ERROR_DATA;
    if (res != SZ_OK)
      goto done;
    if (produced) {
      res = SzStreamWrite(outStream, state.dic + oldPos, produced);
      if (res != SZ_OK)
        goto done;
    }
    remaining -= produced;
    if (state.dicPos == state.dicBufSize)
      state.dicPos = 0;
    if (!produced && !inProcessed) {
      res = SZ_ERROR_DATA;
      goto done;
    }
    if (remaining == 0) {
      if (status != LZMA_STATUS_FINISHED_WITH_MARK &&
          status != LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK)
        res = SZ_ERROR_DATA;
      else if (inSize != 0)
        res = SZ_ERROR_DATA;
      goto done;
    }
  }
  res = SZ_ERROR_DATA;

done:
  IAlloc_Free(allocMain, dict);
  LzmaDec_FreeProbs(&state, allocMain);
  return res;
}

static SRes SzDecodeLzma2ToStream(const CSzCoderInfo *coder, UInt64 inSize, UInt64 outSize,
    ILookInStream *inStream, ISeqOutStream *outStream, ISzAlloc *allocMain)
{
  CLzma2Dec state;
  Byte *dict = NULL;
  UInt64 remaining = outSize;
  SRes res;

  if (outSize == 0)
    return SZ_OK;
  Lzma2Dec_Construct(&state);
  if (coder->Props.size != 1)
    return SZ_ERROR_DATA;
  RINOK(Lzma2Dec_AllocateProbs(&state, coder->Props.data[0], allocMain));
  if (outSize < state.decoder.prop.dicSize)
    state.decoder.prop.dicSize = (UInt32)outSize;
  if (state.decoder.prop.dicSize != 0) {
    dict = (Byte *)IAlloc_Alloc(allocMain, state.decoder.prop.dicSize);
    if (!dict) {
      Lzma2Dec_FreeProbs(&state, allocMain);
      return SZ_ERROR_MEM;
    }
  }
  state.decoder.dic        = dict;
  state.decoder.dicBufSize = state.decoder.prop.dicSize;
  Lzma2Dec_Init(&state);

  while (remaining > 0) {
    const void *inBuf;
    size_t lookahead = (1 << 18);
    size_t oldPos, inProcessed;
    SizeT dicLimit, outputWindow, produced;
    ELzmaStatus status;
    ELzmaFinishMode finishMode;

    if (lookahead > inSize)
      lookahead = (size_t)inSize;
    if (!lookahead) {
      res = SZ_ERROR_INPUT_EOF;
      goto done;
    }
    res = inStream->Look((void *)inStream, &inBuf, &lookahead);
    if (res != SZ_OK)
      goto done;
    if (!lookahead) {
      res = SZ_ERROR_INPUT_EOF;
      goto done;
    }
    oldPos = state.decoder.dicPos;
    outputWindow = state.decoder.dicBufSize - state.decoder.dicPos;
    if (outputWindow > SZ_DECODE_OUTPUT_WINDOW_SIZE)
      outputWindow = SZ_DECODE_OUTPUT_WINDOW_SIZE;
    if ((UInt64)outputWindow > remaining)
      outputWindow = (SizeT)remaining;
    if (outputWindow == 0) {
      res = SZ_ERROR_DATA;
      goto done;
    }
    dicLimit = state.decoder.dicPos + outputWindow;
    finishMode = remaining <= outputWindow ? LZMA_FINISH_END : LZMA_FINISH_ANY;
    inProcessed = lookahead;
    res = Lzma2Dec_DecodeToDic(&state, dicLimit, (const Byte *)inBuf,
                               &inProcessed, finishMode, &status);
    if (!SzDecoderInputProgressAllowed(inSize, lookahead, inProcessed)) {
      res = SZ_ERROR_DATA;
      goto done;
    }
    if (inProcessed) {
      res = inStream->Skip((void *)inStream, inProcessed);
      if (res != SZ_OK)
        goto done;
    }
    inSize -= inProcessed;
    if (state.decoder.dicPos < oldPos)
      res = SZ_ERROR_DATA;
    produced = state.decoder.dicPos - oldPos;
    if ((UInt64)produced > remaining)
      res = SZ_ERROR_DATA;
    if (res != SZ_OK)
      goto done;
    if (produced) {
      res = SzStreamWrite(outStream, state.decoder.dic + oldPos, produced);
      if (res != SZ_OK)
        goto done;
    }
    remaining -= produced;
    if (state.decoder.dicPos == state.decoder.dicBufSize)
      state.decoder.dicPos = 0;
    if (!produced && !inProcessed) {
      res = SZ_ERROR_DATA;
      goto done;
    }
    if (remaining == 0) {
      if (status != LZMA_STATUS_FINISHED_WITH_MARK)
        res = SZ_ERROR_DATA;
      else if (inSize != 0)
        res = SZ_ERROR_DATA;
      goto done;
    }
  }
  res = SZ_ERROR_DATA;

done:
  IAlloc_Free(allocMain, dict);
  Lzma2Dec_FreeProbs(&state, allocMain);
  return res;
}

static SRes SzDecodePpmdToStream(const CSzCoderInfo *coder, UInt64 inSize, UInt64 outSize,
    ILookInStream *inStream, ISeqOutStream *outStream, ISzAlloc *allocMain)
{
  CPpmd7 ppmd;
  CByteInToLook s;
  UInt64 remaining = outSize;
  SRes res = SZ_OK;

  if (outSize == 0)
    return SZ_OK;
  s.p.Read = ReadByte;
  s.inStream = inStream;
  s.begin = s.end = s.cur = NULL;
  s.extra = False;
  s.res = SZ_OK;
  s.processed = 0;
  s.limit = inSize;
  if (coder->Props.size != 5)
    return SZ_ERROR_UNSUPPORTED;
  {
    unsigned order = coder->Props.data[0];
    UInt32 memSize = GetUi32(coder->Props.data + 1);
    if (order < PPMD7_MIN_ORDER || order > PPMD7_MAX_ORDER ||
        memSize < PPMD7_MIN_MEM_SIZE || memSize > PPMD7_MAX_MEM_SIZE)
      return SZ_ERROR_UNSUPPORTED;
    Ppmd7_Construct(&ppmd);
    if (!Ppmd7_Alloc(&ppmd, memSize, allocMain))
      return SZ_ERROR_MEM;
    Ppmd7_Init(&ppmd, order);
  }
  {
    CPpmd7z_RangeDec rc;
    Ppmd7z_RangeDec_CreateVTable(&rc);
    rc.Stream = &s.p;
    if (!Ppmd7z_RangeDec_Init(&rc))
      res = SZ_ERROR_DATA;
    while (res == SZ_OK && remaining > 0) {
      Byte out[1 << 18];
      size_t count = remaining > sizeof(out) ? sizeof(out) : (size_t)remaining;
      size_t i;
      for (i = 0; i < count; i++) {
        int sym = Ppmd7_DecodeSymbol(&ppmd, &rc.p);
        if (s.extra || sym < 0) {
          res = SZ_ERROR_DATA;
          break;
        }
        out[i] = (Byte)sym;
      }
      if (res == SZ_OK) {
        res = SzStreamWrite(outStream, out, count);
        remaining -= count;
      }
    }
    if (res == SZ_OK && remaining == 0 &&
        (!SzPpmdInputAccountingAllowed(s.processed, s.cur - s.begin, inSize) ||
         s.processed + (UInt64)(s.cur - s.begin) != inSize ||
         !Ppmd7z_RangeDec_IsFinishedOK(&rc)))
      res = SZ_ERROR_DATA;
  }
  Ppmd7_Free(&ppmd, allocMain);
  return res;
}

static Bool IS_MAIN_METHOD(UInt32 m)
{
  switch(m)
  {
    case k_Copy:
    case k_LZMA:
    case k_LZMA2:
    #ifdef _7ZIP_PPMD_SUPPPORT
    case k_PPMD:
    #endif
      return True;
  }
  return False;
}

static Bool IS_SUPPORTED_CODER(const CSzCoderInfo *c)
{
  return
      c->NumInStreams == 1 &&
      c->NumOutStreams == 1 &&
      c->MethodID <= (UInt32)0xFFFFFFFF &&
      IS_MAIN_METHOD((UInt32)c->MethodID);
}

#define IS_BCJ2(c) ((c)->MethodID == k_BCJ2 && (c)->NumInStreams == 4 && (c)->NumOutStreams == 1)

static SRes CheckSupportedFolder(const CSzFolder *f)
{
  if (f->NumCoders < 1 || f->NumCoders > 4)
    return SZ_ERROR_UNSUPPORTED;

  if (f->Coders[0].MethodID == 0x06F10701) /* ACAB */
    return SZ_ERROR_ENCRYPTED;

  if (!IS_SUPPORTED_CODER(&f->Coders[0]))
    return SZ_ERROR_UNSUPPORTED;
  if (f->NumCoders == 1)
  {
    if (f->NumPackStreams != 1 || f->PackStreams[0] != 0 || f->NumBindPairs != 0)
      return SZ_ERROR_UNSUPPORTED;
    return SZ_OK;
  }
  if (f->NumCoders == 2)
  {
    CSzCoderInfo *c = &f->Coders[1];
    if (c->MethodID > (UInt32)0xFFFFFFFF ||
        c->NumInStreams != 1 ||
        c->NumOutStreams != 1 ||
        f->NumPackStreams != 1 ||
        f->PackStreams[0] != 0 ||
        f->NumBindPairs != 1 ||
        f->BindPairs[0].InIndex != 1 ||
        f->BindPairs[0].OutIndex != 0)
      return SZ_ERROR_UNSUPPORTED;
    switch ((UInt32)c->MethodID)
    {
      case k_BCJ:
      case k_ARM:
        break;
      default:
        return SZ_ERROR_UNSUPPORTED;
    }
    return SZ_OK;
  }
  if (f->NumCoders == 4)
  {
    if (!IS_SUPPORTED_CODER(&f->Coders[1]) ||
        !IS_SUPPORTED_CODER(&f->Coders[2]) ||
        !IS_BCJ2(&f->Coders[3]))
      return SZ_ERROR_UNSUPPORTED;
    if (f->NumPackStreams != 4 ||
        f->PackStreams[0] != 2 ||
        f->PackStreams[1] != 6 ||
        f->PackStreams[2] != 1 ||
        f->PackStreams[3] != 0 ||
        f->NumBindPairs != 3 ||
        f->BindPairs[0].InIndex != 5 || f->BindPairs[0].OutIndex != 0 ||
        f->BindPairs[1].InIndex != 4 || f->BindPairs[1].OutIndex != 1 ||
        f->BindPairs[2].InIndex != 3 || f->BindPairs[2].OutIndex != 2)
      return SZ_ERROR_UNSUPPORTED;
    return SZ_OK;
  }
  return SZ_ERROR_UNSUPPORTED;
}

static SRes SzPackStreamPosition(const UInt64 *packSizes, UInt32 packIndex,
    UInt64 startPos, UInt64 *position)
{
  UInt64 offset = 0;
  UInt32 i;

  if (packSizes == 0 || position == 0)
    return SZ_ERROR_PARAM;
  for (i = 0; i < packIndex; i++)
  {
    if ((UInt64)-1 - offset < packSizes[i])
      return SZ_ERROR_DATA;
    offset += packSizes[i];
  }
  if ((UInt64)-1 - startPos < offset)
    return SZ_ERROR_DATA;
  *position = startPos + offset;
  return SZ_OK;
}

#define CASE_BRA_CONV(isa) case k_ ## isa: isa ## _Convert(outBuffer, outSize, 0, 0); break;

static SRes SzFolder_Decode2(const CSzFolder *folder, const UInt64 *packSizes,
    ILookInStream *inStream, UInt64 startPos,
    Byte *outBuffer, SizeT outSize, ISzAlloc *allocMain,
    Byte *tempBuf[])
{
  UInt32 ci;
  SizeT tempSizes[3] = { 0, 0, 0};
  SizeT tempSize3 = 0;
  Byte *tempBuf3 = 0;

  RINOK(CheckSupportedFolder(folder));

  for (ci = 0; ci < folder->NumCoders; ci++)
  {
    CSzCoderInfo *coder = &folder->Coders[ci];

    if (IS_MAIN_METHOD((UInt32)coder->MethodID))
    {
      UInt32 si = 0;
      UInt64 packPosition;
      UInt64 inSize;
      Byte *outBufCur = outBuffer;
      SizeT outSizeCur = outSize;
      if (folder->NumCoders == 4)
      {
        UInt32 indices[] = { 3, 2, 0 };
        UInt64 unpackSize = folder->UnpackSizes[ci];
        si = indices[ci];
        if (ci < 2)
        {
          Byte *temp;
          outSizeCur = (SizeT)unpackSize;
          if (outSizeCur != unpackSize)
            return SZ_ERROR_MEM;
          temp = (Byte *)IAlloc_Alloc(allocMain, outSizeCur);
          if (temp == 0 && outSizeCur != 0)
            return SZ_ERROR_MEM;
          outBufCur = tempBuf[1 - ci] = temp;
          tempSizes[1 - ci] = outSizeCur;
        }
        else if (ci == 2)
        {
          if (unpackSize > outSize) /* check it */
            return SZ_ERROR_PARAM;
          tempBuf3 = outBufCur = outBuffer + (outSize - (size_t)unpackSize);
          tempSize3 = outSizeCur = (SizeT)unpackSize;
        }
        else
          return SZ_ERROR_UNSUPPORTED;
      }
      if (!packSizes)
        return SZ_ERROR_FAIL;
      inSize = packSizes[si];
      RINOK(SzPackStreamPosition(packSizes, si, startPos, &packPosition));
      RINOK(LookInStream_SeekTo(inStream, packPosition));

      if (coder->MethodID == k_Copy)
      {
        if (inSize != outSizeCur) /* check it */
          return SZ_ERROR_DATA;
        RINOK(SzDecodeCopy(inSize, inStream, outBufCur));
      }
      else if (coder->MethodID == k_LZMA)
      {
        RINOK(SzDecodeLzma(coder, inSize, inStream, outBufCur, outSizeCur, allocMain));
      }
      else if (coder->MethodID == k_LZMA2)
      {
        RINOK(SzDecodeLzma2(coder, inSize, inStream, outBufCur, outSizeCur, allocMain));
      }
      else
      {
        #ifdef _7ZIP_PPMD_SUPPPORT
        RINOK(SzDecodePpmd(coder, inSize, inStream, outBufCur, outSizeCur, allocMain));
        #else
        return SZ_ERROR_UNSUPPORTED;
        #endif
      }
    }
    else if (coder->MethodID == k_BCJ2)
    {
      UInt64 packPosition;
      UInt64 s3Size = packSizes[1];
      SRes res;
      if (ci != 3)
        return SZ_ERROR_UNSUPPORTED;
      RINOK(SzPackStreamPosition(packSizes, 1, startPos, &packPosition));
      RINOK(LookInStream_SeekTo(inStream, packPosition));
      tempSizes[2] = (SizeT)s3Size;
      if (tempSizes[2] != s3Size)
        return SZ_ERROR_MEM;
      tempBuf[2] = (Byte *)IAlloc_Alloc(allocMain, tempSizes[2]);
      if (tempBuf[2] == 0 && tempSizes[2] != 0)
        return SZ_ERROR_MEM;
      res = SzDecodeCopy(s3Size, inStream, tempBuf[2]);
      RINOK(res)

      res = Bcj2_Decode(
          tempBuf3, tempSize3,
          tempBuf[0], tempSizes[0],
          tempBuf[1], tempSizes[1],
          tempBuf[2], tempSizes[2],
          outBuffer, outSize);
      RINOK(res)
    }
    else
    {
      if (ci != 1)
        return SZ_ERROR_UNSUPPORTED;
      switch(coder->MethodID)
      {
        case k_BCJ:
        {
          UInt32 state;
          x86_Convert_Init(state);
          x86_Convert(outBuffer, outSize, 0, &state, 0);
          break;
        }
        CASE_BRA_CONV(ARM)
        default:
          return SZ_ERROR_UNSUPPORTED;
      }
    }
  }
  return SZ_OK;
}

SRes SzFolder_Decode(const CSzFolder *folder, const UInt64 *packSizes,
    ILookInStream *inStream, UInt64 startPos,
    Byte *outBuffer, size_t outSize, ISzAlloc *allocMain)
{
  Byte *tempBuf[3] = { 0, 0, 0};
  int i;
  SRes res = SzFolder_Decode2(folder, packSizes, inStream, startPos,
      outBuffer, (SizeT)outSize, allocMain, tempBuf);
  for (i = 0; i < 3; i++)
    IAlloc_Free(allocMain, tempBuf[i]);
  return res;
}

typedef struct
{
  ISeqOutStream s;
  ISeqOutStream *downstream;
  UInt32 crc;
  UInt64 written;
} CSzCrcOutStream;

static size_t SzCrcOutStream_Write(void *pp, const void *data, size_t size)
{
  CSzCrcOutStream *p = (CSzCrcOutStream *)pp;
  size_t written = p->downstream->Write(p->downstream, data, size);
  if (written) {
    p->crc = CrcUpdate(p->crc, data, written);
    p->written += written;
  }
  return written;
}

typedef struct
{
  ISeqOutStream s;
  ISeqOutStream *downstream;
  ISzBcj2TempStreams *provider;
  SRes status;
} CSzProgressOutStream;

static size_t SzProgressOutStream_Write(void *pp, const void *data,
    size_t size)
{
  CSzProgressOutStream *p = (CSzProgressOutStream *)pp;
  size_t written;

  if (p == 0 || p->downstream == 0 || p->provider == 0 ||
      p->provider->Checkpoint == 0 || p->status != SZ_OK)
    return 0;
  p->status = p->provider->Checkpoint(p->provider->opaque);
  if (p->status != SZ_OK)
    return 0;
  written = p->downstream->Write(p->downstream, data, size);
  if (written != size)
    return written;
  p->status = p->provider->Checkpoint(p->provider->opaque);
  if (p->status != SZ_OK)
    return 0;
  return written;
}

#define SZ_BRANCH_BUFFER_SIZE (1 << 18)

/* A two-coder 7-Zip folder is normally a decompressor followed by a branch
   converter such as BCJ or ARM.  The legacy decoder applied that converter
   in place to the complete solid-folder buffer.  Keep the converter state
   and its small look-ahead window across decoder writes instead, so a large
   solid folder can stay on the sequential bounded-output path. */
typedef struct
{
  ISeqOutStream s;
  ISeqOutStream *downstream;
  UInt32 method;
  UInt32 ip;
  UInt32 x86State;
  Byte *buf;
  size_t capacity;
  size_t bufPos;
  size_t bufConv;
  size_t bufTotal;
} CSzBranchOutStream;

static int SzBranchOutStream_Drain(CSzBranchOutStream *p)
{
  while (p->bufPos != p->bufConv) {
    size_t remaining = p->bufConv - p->bufPos;
    size_t written   = p->downstream->Write(p->downstream, p->buf + p->bufPos, remaining);
    if (written != remaining)
      return 0;
    p->bufPos += written;
  }
  return 1;
}

static void SzBranchOutStream_Compact(CSzBranchOutStream *p)
{
  if (p->bufPos != 0) {
    p->bufTotal -= p->bufPos;
    if (p->bufTotal != 0)
      memmove(p->buf, p->buf + p->bufPos, p->bufTotal);
    p->bufPos  = 0;
    p->bufConv = 0;
  }
}

static size_t SzBranchOutStream_Convert(CSzBranchOutStream *p, int finished)
{
  size_t converted;

  switch (p->method) {
    case k_BCJ:
      converted = x86_Convert(p->buf, p->bufTotal, p->ip, &p->x86State, 0);
      break;
    case k_ARM:
      converted = ARM_Convert(p->buf, p->bufTotal, p->ip, 0);
      break;
    default:
      return 0;
  }

  /* The converters intentionally keep their alignment/look-ahead tail for
     the next call.  Once the decompressor has finished, those bytes are a
     complete final block and must be emitted unchanged if no conversion is
     possible. */
  if (converted == 0 && finished)
    converted = p->bufTotal;

  p->bufConv = converted;
  p->ip += (UInt32)converted;
  return converted;
}

static size_t SzBranchOutStream_Write(void *pp, const void *data, size_t size)
{
  CSzBranchOutStream *p = (CSzBranchOutStream *)pp;
  const Byte *src       = (const Byte *)data;
  size_t consumed       = 0;

  while (consumed < size) {
    size_t available;
    size_t copied;

    if (!SzBranchOutStream_Drain(p))
      return 0;
    SzBranchOutStream_Compact(p);

    if (p->bufTotal == p->capacity) {
      if (SzBranchOutStream_Convert(p, 0) == 0)
        return 0;
      continue;
    }

    available = p->capacity - p->bufTotal;
    copied    = size - consumed;
    if (copied > available)
      copied = available;
    memcpy(p->buf + p->bufTotal, src + consumed, copied);
    p->bufTotal += copied;
    consumed += copied;

    if (p->bufTotal != 0 && SzBranchOutStream_Convert(p, 0) != 0) {
      if (!SzBranchOutStream_Drain(p))
        return 0;
      SzBranchOutStream_Compact(p);
    }
  }

  return size;
}

static SRes SzBranchOutStream_Finish(CSzBranchOutStream *p)
{
  while (p->bufTotal != 0 || p->bufPos != p->bufConv) {
    if (!SzBranchOutStream_Drain(p))
      return SZ_ERROR_WRITE;
    SzBranchOutStream_Compact(p);
    if (p->bufTotal == 0)
      break;
    if (SzBranchOutStream_Convert(p, 1) == 0)
      return SZ_ERROR_DATA;
  }
  return SZ_OK;
}

static SRes SzDecodeMainCoderToStream(const CSzCoderInfo *coder,
    UInt64 inSize, UInt64 outSize, ILookInStream *inStream,
    ISeqOutStream *outStream, ISzAlloc *allocMain)
{
  switch ((UInt32)coder->MethodID)
  {
    case k_Copy:
      if (inSize != outSize)
        return SZ_ERROR_DATA;
      return SzDecodeCopyToStream(inSize, inStream, outStream);
    case k_LZMA:
      return SzDecodeLzmaToStream((CSzCoderInfo *)coder, inSize, outSize,
          inStream, outStream, allocMain);
    case k_LZMA2:
      return SzDecodeLzma2ToStream((CSzCoderInfo *)coder, inSize, outSize,
          inStream, outStream, allocMain);
#ifdef _7ZIP_PPMD_SUPPPORT
    case k_PPMD:
      return SzDecodePpmdToStream((CSzCoderInfo *)coder, inSize, outSize,
          inStream, outStream, allocMain);
#endif
    default:
      return SZ_ERROR_UNSUPPORTED;
  }
}

SRes SzFolder_DecodeToStreamEx(const CSzFolder *folder, const UInt64 *packSizes,
    ILookInStream *inStream, UInt64 startPos,
    ISeqOutStream *outStream, ISzAlloc *allocMain,
    ISzBcj2TempStreams *tempStreams)
{
  CSzCrcOutStream crcStream;
  CSzProgressOutStream progressStream;
  CSzBranchOutStream branchStream;
  ISeqOutStream *target = outStream;
  Byte *branchBuffer = NULL;
  UInt64 outSize;
  SRes res;

  if (!folder || !packSizes || !inStream || !outStream)
    return SZ_ERROR_PARAM;
  if (folder->NumCoders != 1 && folder->NumCoders != 2 &&
      folder->NumCoders != 4)
    return SZ_ERROR_UNSUPPORTED;
  res = CheckSupportedFolder(folder);
  if (res != SZ_OK)
    return res;
  outSize = SzFolder_GetUnpackSize((CSzFolder *)folder);

  memset(&crcStream, 0, sizeof(crcStream));
  crcStream.s.Write  = SzCrcOutStream_Write;
  crcStream.downstream = outStream;
  crcStream.crc     = CRC_INIT_VAL;
  target            = &crcStream.s;

  memset(&progressStream, 0, sizeof(progressStream));
  if (tempStreams != 0 && tempStreams->Checkpoint != 0)
  {
    progressStream.s.Write = SzProgressOutStream_Write;
    progressStream.downstream = target;
    progressStream.provider = tempStreams;
    progressStream.status = tempStreams->Checkpoint(tempStreams->opaque);
    if (progressStream.status != SZ_OK)
      return progressStream.status;
    target = &progressStream.s;
  }

  memset(&branchStream, 0, sizeof(branchStream));
  if (folder->NumCoders == 2) {
    branchBuffer = (Byte *)IAlloc_Alloc(allocMain, SZ_BRANCH_BUFFER_SIZE);
    if (branchBuffer == NULL)
      return SZ_ERROR_MEM;
    branchStream.s.Write = SzBranchOutStream_Write;
    branchStream.downstream = target;
    branchStream.method = (UInt32)folder->Coders[1].MethodID;
    branchStream.buf = branchBuffer;
    branchStream.capacity = SZ_BRANCH_BUFFER_SIZE;
    x86_Convert_Init(branchStream.x86State);
    target = &branchStream.s;
  }

  if (folder->NumCoders == 4)
  {
    static const UInt32 packIndices[2] = { 3, 2 };
    static const UInt32 inputIndices[2] = { 2, 1 };
    ISeqInStream *bcj2Inputs[4] = { 0, 0, 0, 0 };
    UInt64 bcj2Sizes[4] = { 0, 0, 0, 0 };
    CBcj2MainOutStream *bcj2 = 0;
    UInt32 ci;

    if (tempStreams == 0 || tempStreams->Create == 0 ||
        tempStreams->Finish == 0)
    {
      res = SZ_ERROR_UNSUPPORTED;
      goto verify;
    }

    for (ci = 0; ci < 2; ci++)
    {
      UInt32 inputIndex = inputIndices[ci];
      UInt32 packIndex = packIndices[ci];
      ISeqOutStream *scratchOut = 0;
      UInt64 packPosition;

      bcj2Sizes[inputIndex] = folder->UnpackSizes[ci];
      res = tempStreams->Create(tempStreams->opaque, inputIndex,
          bcj2Sizes[inputIndex], &scratchOut);
      if (res != SZ_OK)
        goto verify;
      res = SzPackStreamPosition(packSizes, packIndex, startPos,
          &packPosition);
      if (res != SZ_OK)
        goto verify;
      res = LookInStream_SeekTo(inStream, packPosition);
      if (res != SZ_OK)
        goto verify;
      res = SzDecodeMainCoderToStream(&folder->Coders[ci],
          packSizes[packIndex], bcj2Sizes[inputIndex], inStream,
          scratchOut, allocMain);
      if (res != SZ_OK)
        goto verify;
      res = tempStreams->Finish(tempStreams->opaque, inputIndex,
          &bcj2Inputs[inputIndex]);
      if (res != SZ_OK)
        goto verify;
    }

    bcj2Sizes[3] = packSizes[1];
    {
      ISeqOutStream *scratchOut = 0;
      UInt64 packPosition;
      res = tempStreams->Create(tempStreams->opaque, 3, bcj2Sizes[3],
          &scratchOut);
      if (res != SZ_OK)
        goto verify;
      res = SzPackStreamPosition(packSizes, 1, startPos, &packPosition);
      if (res != SZ_OK)
        goto verify;
      res = LookInStream_SeekTo(inStream, packPosition);
      if (res != SZ_OK)
        goto verify;
      res = SzDecodeCopyToStream(packSizes[1], inStream, scratchOut);
      if (res != SZ_OK)
        goto verify;
      res = tempStreams->Finish(tempStreams->opaque, 3, &bcj2Inputs[3]);
      if (res != SZ_OK)
        goto verify;
    }

    bcj2Sizes[0] = folder->UnpackSizes[2];
    res = Bcj2MainOutStream_Create(&bcj2, bcj2Inputs, bcj2Sizes,
        outSize, target, allocMain);
    if (res == SZ_OK)
    {
      UInt64 packPosition;
      res = SzPackStreamPosition(packSizes, 0, startPos, &packPosition);
      if (res == SZ_OK)
        res = LookInStream_SeekTo(inStream, packPosition);
      if (res == SZ_OK)
        res = SzDecodeMainCoderToStream(&folder->Coders[2], packSizes[0],
            bcj2Sizes[0], inStream, Bcj2MainOutStream_GetStream(bcj2),
            allocMain);
      {
        SRes finishRes = Bcj2MainOutStream_Finish(bcj2);
        if (finishRes != SZ_OK && (res == SZ_OK || res == SZ_ERROR_WRITE))
          res = finishRes;
      }
    }
    Bcj2MainOutStream_Free(bcj2, allocMain);
  }
  else
  {
    res = LookInStream_SeekTo(inStream, startPos);
    if (res == SZ_OK)
      res = SzDecodeMainCoderToStream(&folder->Coders[0], packSizes[0],
          outSize, inStream, target, allocMain);
    if (res == SZ_OK && folder->NumCoders == 2)
      res = SzBranchOutStream_Finish(&branchStream);
  }

verify:
  if (progressStream.status != SZ_OK &&
      (res == SZ_OK || res == SZ_ERROR_WRITE))
    res = progressStream.status;
  if (res == SZ_OK) {
    if (crcStream.written != outSize)
      res = SZ_ERROR_DATA;
    else if (folder->UnpackCRCDefined && CRC_GET_DIGEST(crcStream.crc) != folder->UnpackCRC)
      res = SZ_ERROR_CRC;
  }

  IAlloc_Free(allocMain, branchBuffer);
  return res;
}

SRes SzFolder_DecodeToStream(const CSzFolder *folder, const UInt64 *packSizes,
    ILookInStream *inStream, UInt64 startPos,
    ISeqOutStream *outStream, ISzAlloc *allocMain)
{
  return SzFolder_DecodeToStreamEx(folder, packSizes, inStream, startPos,
      outStream, allocMain, 0);
}
