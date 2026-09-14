/* 7zStream.c -- 7z Stream functions
2010-03-11 : Igor Pavlov : Public domain */

#include <string.h>

#include "Types.h"

SRes SeqInStream_Read2(ISeqInStream *stream, void *buf, size_t size, SRes errorType)
{
  if (stream == NULL || stream->Read == NULL || (size != 0 && buf == NULL))
    return SZ_ERROR_PARAM;

  while (size != 0)
  {
    size_t requested = size;
    size_t processed = requested;
    RINOK(stream->Read(stream, buf, &processed));
    if (processed > requested)
      return SZ_ERROR_FAIL;
    if (processed == 0)
      return errorType;
    buf = (void *)((Byte *)buf + processed);
    size -= processed;
  }
  return SZ_OK;
}

SRes SeqInStream_Read(ISeqInStream *stream, void *buf, size_t size)
{
  return SeqInStream_Read2(stream, buf, size, SZ_ERROR_INPUT_EOF);
}

SRes SeqInStream_ReadByte(ISeqInStream *stream, Byte *buf)
{
  size_t processed;

  if (stream == NULL || stream->Read == NULL || buf == NULL)
    return SZ_ERROR_PARAM;

  processed = 1;
  RINOK(stream->Read(stream, buf, &processed));
  if (processed > 1)
    return SZ_ERROR_FAIL;
  return (processed == 1) ? SZ_OK : SZ_ERROR_INPUT_EOF;
}

SRes LookInStream_SeekTo(ILookInStream *stream, UInt64 offset)
{
  Int64 t;

  if (stream == NULL || stream->Seek == NULL)
    return SZ_ERROR_PARAM;

  /* The SDK seek callback uses a signed Int64 position. Do not let a
     representable UInt64 archive coordinate wrap into a different location
     before the callback sees it. */
  if (offset > ((UInt64)-1 >> 1))
    return SZ_ERROR_DATA;
  t = (Int64)offset;
  return stream->Seek(stream, &t, SZ_SEEK_SET);
}

SRes LookInStream_LookRead(ILookInStream *stream, void *buf, size_t *size)
{
  const void *lookBuf = NULL;
  size_t requested;

  if (stream == NULL || stream->Look == NULL || stream->Skip == NULL || size == NULL ||
      (*size != 0 && buf == NULL))
    return SZ_ERROR_PARAM;
  if (*size == 0)
    return SZ_OK;
  requested = *size;
  RINOK(stream->Look(stream, &lookBuf, size));
  if (*size > requested || (*size != 0 && lookBuf == NULL))
    return SZ_ERROR_FAIL;
  memcpy(buf, lookBuf, *size);
  return stream->Skip(stream, *size);
}

SRes LookInStream_Read2(ILookInStream *stream, void *buf, size_t size, SRes errorType)
{
  if (stream == NULL || stream->Read == NULL || (size != 0 && buf == NULL))
    return SZ_ERROR_PARAM;

  while (size != 0)
  {
    size_t requested = size;
    size_t processed = requested;
    RINOK(stream->Read(stream, buf, &processed));
    if (processed > requested)
      return SZ_ERROR_FAIL;
    if (processed == 0)
      return errorType;
    buf = (void *)((Byte *)buf + processed);
    size -= processed;
  }
  return SZ_OK;
}

SRes LookInStream_Read(ILookInStream *stream, void *buf, size_t size)
{
  return LookInStream_Read2(stream, buf, size, SZ_ERROR_INPUT_EOF);
}

static SRes LookToRead_Look_Lookahead(void *pp, const void **buf, size_t *size)
{
  SRes res = SZ_OK;
  CLookToRead *p = (CLookToRead *)pp;
  size_t size2;

  if (p == NULL || buf == NULL || size == NULL || p->size > LookToRead_BUF_SIZE ||
      p->pos > p->size)
    return SZ_ERROR_PARAM;

  size2 = p->size - p->pos;
  if (size2 == 0 && *size > 0)
  {
    size_t requested;

    if (p->realStream == NULL || p->realStream->Read == NULL)
      return SZ_ERROR_PARAM;
    p->pos = 0;
    size2 = LookToRead_BUF_SIZE;
    requested = size2;
    res = p->realStream->Read(p->realStream, p->buf, &size2);
    if (size2 > requested)
      return SZ_ERROR_FAIL;
    p->size = size2;
  }
  if (size2 < *size)
    *size = size2;
  *buf = p->buf + p->pos;
  return res;
}

static SRes LookToRead_Look_Exact(void *pp, const void **buf, size_t *size)
{
  SRes res = SZ_OK;
  CLookToRead *p = (CLookToRead *)pp;
  size_t size2;

  if (p == NULL || buf == NULL || size == NULL || p->size > LookToRead_BUF_SIZE ||
      p->pos > p->size)
    return SZ_ERROR_PARAM;

  size2 = p->size - p->pos;
  if (size2 == 0 && *size > 0)
  {
    size_t requested;

    if (p->realStream == NULL || p->realStream->Read == NULL)
      return SZ_ERROR_PARAM;
    p->pos = 0;
    if (*size > LookToRead_BUF_SIZE)
      *size = LookToRead_BUF_SIZE;
    requested = *size;
    res = p->realStream->Read(p->realStream, p->buf, size);
    if (*size > requested)
      return SZ_ERROR_FAIL;
    size2 = p->size = *size;
  }
  if (size2 < *size)
    *size = size2;
  *buf = p->buf + p->pos;
  return res;
}

static SRes LookToRead_Skip(void *pp, size_t offset)
{
  CLookToRead *p = (CLookToRead *)pp;

  if (p == NULL || p->size > LookToRead_BUF_SIZE || p->pos > p->size ||
      offset > p->size - p->pos)
    return SZ_ERROR_PARAM;
  p->pos += offset;
  return SZ_OK;
}

static SRes LookToRead_Read(void *pp, void *buf, size_t *size)
{
  CLookToRead *p = (CLookToRead *)pp;
  size_t rem;

  if (p == NULL || size == NULL || p->pos > p->size ||
      p->size > LookToRead_BUF_SIZE || (*size != 0 && buf == NULL))
    return SZ_ERROR_PARAM;

  if (*size == 0)
    return SZ_OK;

  rem = p->size - p->pos;
  if (rem == 0)
  {
    size_t requested = *size;
    SRes res;

    if (p->realStream == NULL || p->realStream->Read == NULL)
      return SZ_ERROR_PARAM;
    res = p->realStream->Read(p->realStream, buf, size);
    if (*size > requested)
      return SZ_ERROR_FAIL;
    return res;
  }
  if (rem > *size)
    rem = *size;
  memcpy(buf, p->buf + p->pos, rem);
  p->pos += rem;
  *size = rem;
  return SZ_OK;
}

static SRes LookToRead_Seek(void *pp, Int64 *pos, ESzSeek origin)
{
  CLookToRead *p = (CLookToRead *)pp;

  if (p == NULL || pos == NULL || p->realStream == NULL || p->realStream->Seek == NULL)
    return SZ_ERROR_PARAM;
  p->pos = p->size = 0;
  return p->realStream->Seek(p->realStream, pos, origin);
}

void LookToRead_CreateVTable(CLookToRead *p, int lookahead)
{
  p->s.Look = lookahead ?
      LookToRead_Look_Lookahead :
      LookToRead_Look_Exact;
  p->s.Skip = LookToRead_Skip;
  p->s.Read = LookToRead_Read;
  p->s.Seek = LookToRead_Seek;
}

void LookToRead_Init(CLookToRead *p)
{
  p->pos = p->size = 0;
}

static SRes SecToLook_Read(void *pp, void *buf, size_t *size)
{
  CSecToLook *p = (CSecToLook *)pp;

  if (p == NULL || p->realStream == NULL || p->realStream->Look == NULL ||
      p->realStream->Skip == NULL || size == NULL || (*size != 0 && buf == NULL))
    return SZ_ERROR_PARAM;
  return LookInStream_LookRead(p->realStream, buf, size);
}

void SecToLook_CreateVTable(CSecToLook *p)
{
  p->s.Read = SecToLook_Read;
}

static SRes SecToRead_Read(void *pp, void *buf, size_t *size)
{
  CSecToRead *p = (CSecToRead *)pp;
  size_t requested;
  SRes res;

  if (p == NULL || p->realStream == NULL || p->realStream->Read == NULL || size == NULL ||
      (*size != 0 && buf == NULL))
    return SZ_ERROR_PARAM;
  if (*size == 0)
    return SZ_OK;
  requested = *size;
  res = p->realStream->Read(p->realStream, buf, size);
  if (*size > requested)
    return SZ_ERROR_FAIL;
  return res;
}

void SecToRead_CreateVTable(CSecToRead *p)
{
  p->s.Read = SecToRead_Read;
}
