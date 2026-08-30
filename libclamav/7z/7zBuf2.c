/* 7zBuf2.c -- Byte Buffer
2008-10-04 : Igor Pavlov : Public domain */

#include <string.h>

#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#endif

#include "7zBuf.h"

void DynBuf_Construct(CDynBuf *p)
{
  p->data = 0;
  p->size = 0;
  p->pos = 0;
}

void DynBuf_SeekToBeg(CDynBuf *p)
{
  p->pos = 0;
}

int DynBuf_Write(CDynBuf *p, const Byte *buf, size_t size, ISzAlloc *alloc)
{
  size_t newSize;
  Byte *data;

  if (p == 0 || alloc == 0 || p->pos > p->size || (size != 0 && buf == 0))
    return 0;

  /* A zero-length append is a valid no-op, including for an empty buffer. */
  if (size == 0)
    return 1;

  if (size > p->size - p->pos)
  {
    if (size > (size_t)-1 - p->pos)
      return 0;
    newSize = p->pos + size;
    if (newSize > (size_t)-1 - newSize / 4)
      return 0;
    newSize += newSize / 4;
    data = (Byte *)alloc->Alloc(alloc, newSize);
    if (data == 0)
      return 0;
    p->size = newSize;
    if (p->pos != 0)
      memcpy(data, p->data, p->pos);
    alloc->Free(alloc, p->data);
    p->data = data;
  }
  memcpy(p->data + p->pos, buf, size);
  p->pos += size;
  return 1;
}

void DynBuf_Free(CDynBuf *p, ISzAlloc *alloc)
{
  alloc->Free(alloc, p->data);
  p->data = 0;
  p->size = 0;
  p->pos = 0;
}
