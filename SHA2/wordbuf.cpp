#include "stdafx.h"
#include "wordbuf.h"
//Turns a 4-byte buffer into an unsigned integer
uint32_t getword(uint8_t const * buf)
{
	uint32_t val = 0;
	for (int i = 0; i < 4; ++i)
		val += uint32_t(buf[i]) << (8 * (3 - i));
	return val;
}

//Turns an unsigned integer into a 4-byte buffer
void writeword(uint32_t wrd, uint8_t * buf)
{
	for (int i = 0; i < 4; ++i)
	{
		buf[3 - i] = wrd & 0xFF;
		wrd >>= 8;
	}
}

//Turns an 8-byte buffer into an unsigned 64-bit integer
uint64_t getword64(uint8_t const * buf)
{
	uint64_t val = 0;
	for (int i = 0; i < 8; ++i)
		val += uint64_t(buf[i]) << (8 * (7 - i));
	return val;
}

//Turns an unsigned 64-bit integer into an 8-byte buffer
void writeword64(uint64_t wrd, uint8_t * buf)
{
	for (int i = 0; i < 8; ++i)
	{
		buf[7 - i] = wrd & 0xFF;
		wrd >>= 8;
	}
}