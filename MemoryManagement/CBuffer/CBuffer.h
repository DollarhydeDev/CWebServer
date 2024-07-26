#pragma once

class CBuffer
{
public:
	CBuffer();
	~CBuffer();

	void AllocateCharBuffer(unsigned short size);
	char* GetCharBuffer();
	unsigned short GetCharBufferSize();

	void AllocateWCharBuffer(unsigned short size);
	wchar_t* GetWCharBuffer();
	unsigned short GetWCharBufferSize();

private:
	char* charBuffer;
	unsigned short charBufferSize;

	wchar_t* wcharBuffer;
	unsigned short wcharBufferSize;

	void DeallocateBuffers();
};

