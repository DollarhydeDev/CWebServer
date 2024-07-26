#include "CBuffer.h"

CBuffer::CBuffer() : charBuffer(nullptr), charBufferSize(0), wcharBuffer(nullptr), wcharBufferSize(0)
{
}
CBuffer::~CBuffer()
{
	DeallocateBuffers();
}

void CBuffer::AllocateCharBuffer(unsigned short size)
{
	if (charBuffer != nullptr)
	{
		DeallocateBuffers();
	}

	charBuffer = new char[size];
	charBufferSize = size;
}
char* CBuffer::GetCharBuffer()
{
	return charBuffer;
}
unsigned short CBuffer::GetCharBufferSize()
{
	return charBufferSize;
}

void CBuffer::AllocateWCharBuffer(unsigned short size)
{
	if (wcharBuffer != nullptr)
	{
		DeallocateBuffers();
	}

	wcharBuffer = new wchar_t[size];
	wcharBufferSize = size;
}
wchar_t* CBuffer::GetWCharBuffer()
{
	return wcharBuffer;
}
unsigned short CBuffer::GetWCharBufferSize()
{
	return wcharBufferSize;
}

void CBuffer::DeallocateBuffers()
{
	if (charBuffer != nullptr)
	{
		delete[] charBuffer;
		charBuffer = nullptr;
		charBufferSize = 0;
	}

	if (wcharBuffer != nullptr)
	{
		delete[] wcharBuffer;
		wcharBuffer = nullptr;
		wcharBufferSize = 0;
	}
}
