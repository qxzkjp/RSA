#include "stdafx.h"
#include <stdint.h>
#include <iostream>
#include <sstream>
#include <iomanip>

const uint32_t K32[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t getword(uint8_t* buf)
{
	uint8_t* val = new uint8_t[4];
	for (int i = 0; i < 4; ++i)
	{
		val[3 - i] = buf[i];
	}
	return *(reinterpret_cast<uint32_t*>(val));
}

void pad512(const uint8_t* msg, size_t len, uint8_t* &buf, size_t& newlen)
{
	size_t padcount;
	if (len % 64 >= 56)
	{
		padcount = (64 - (len % 64)) + 56;
	}
	else{
		padcount = 56 - (len % 64);
	}
	newlen = len + padcount + 8;
	buf = new uint8_t[newlen];
	for (int i = 0; i < len; ++i)
	{
		buf[i] = msg[i];
	}
	buf[len] = 0x80;
	for (size_t i = len + 1; i < len + padcount; ++i)
	{
		buf[i] = 0;
	}
	uint64_t biglen = len * 8;
	uint8_t* ptr = reinterpret_cast<uint8_t*>(&biglen);
	for (int i = 0; i < 8; ++i)
	{
		buf[len + padcount + i] = ptr[7 - i];
	}
}

void testpadding(uint8_t* msg, size_t len)
{
	std::ios::fmtflags f(std::cout.flags()); //save cout state
	size_t plen;
	uint8_t* buf = nullptr;
	pad512(msg, len, buf, plen);
	std::cout << std::hex;
	for (size_t i = 0; i < plen; ++i)
	{
		std::cout << (uint32_t)buf[i];
		if (i % 8 == 7)
			std::cout << std::endl;
		else
			std::cout << ", ";
	}
	if ((plen % 64) != 0)
		std::cout << "invalid message length!" << std::endl;
	std::cout.flags(f); //restore cout state
}

inline uint32_t rotr(uint32_t x, size_t shft)
{
	return (x >> shft) + (x << (32 - shft));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y) ^ ((~x)&z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y) ^ (x&z) ^ (y&z);
}

inline uint32_t capsig0(uint32_t x)
{
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t capsig1(uint32_t x)
{
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t sig0(uint32_t x)
{
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t sig1(uint32_t x)
{
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

std::string SHA256(const uint8_t* msg, size_t len)
{
	//set up initial hash values
	uint32_t h[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	uint32_t g[8]; //this is the working vars a...h
	uint8_t* buf = nullptr; //space for the padded message
	size_t chunks;
	//pad message and get number of 512-byte chunks
	pad512(msg, len, buf, chunks);
	chunks /= 64;
	uint32_t w[64]; //message schedule
	for (size_t i = 0; i < chunks; ++i) //loop over chunks
	{
		//pointer to start of chunk
		uint8_t* base = buf + (i * 64);
		//fill first 16 words of schedule with message chunk
		for (int j = 0; j < 16; ++j)
		{
			w[j] = getword(base + (4 * j));
		}
		for (int j = 16; j < 64; ++j)
		{
			w[j] = sig1(w[j - 2]) + w[j - 7] + sig0(w[j - 15]) + w[j - 16];
		}
		//copy hash values into working variables
		for (int j = 0; j < 8; ++j)
			g[j] = h[j];
		//main compression loop
		for (int t = 0; t < 64; ++t)
		{
			uint32_t tmp1 = g[7] + capsig1(g[4]) + ch(g[4], g[5], g[6]) + K32[t] + w[t];
			uint32_t tmp2 = capsig0(g[0]) + maj(g[0], g[1], g[2]);
			for (int i = 7; i > 0; --i)
				g[i] = g[i - 1];
			g[4] += tmp1;
			g[0] = tmp1 + tmp2;
		}
		//add result to hash
		for (int j = 0; j < 8; ++j)
			h[j] += g[j];
	}

	//finally -- concatenate hex strings
	std::stringstream stream;
	stream << std::hex << std::uppercase;
	for (int i = 0; i <8; ++i)
		stream << std::setfill('0') << std::setw(8) << h[i]; //print 8 hex digits for each number
	return stream.str();
}