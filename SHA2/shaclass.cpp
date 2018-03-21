#include "stdafx.h"
#include "shaclass.h"
#include "wordbuf.h"
#include <iostream>
#include "HMAC.h"

//key constants for SHA256 and SHA224
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

//Key constants for SHA512
const uint64_t K64[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

template<typename T>
inline T min(T a, T b)
{
	if (a < b)
		return a;
	else
		return b;
}

template<class T>
inline T ch(T x, T y, T z)
{
	return (x&y) ^ ((~x)&z);
}

template<class T>
inline T maj(T x, T y, T z)
{
	return (x&y) ^ (x&z) ^ (y&z);
}

inline uint32_t parity(uint32_t x, uint32_t y, uint32_t z)
{
	return x^y^z;
}

inline uint32_t capsig0(uint32_t x)
{
	return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22);
}

inline uint64_t capsig0(uint64_t x)
{
	return _rotr64(x, 28) ^ _rotr64(x, 34) ^ _rotr64(x, 39);
}

inline uint32_t capsig1(uint32_t x)
{
	return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25);
}

inline uint64_t capsig1(uint64_t x)
{
	return _rotr64(x, 14) ^ _rotr64(x, 18) ^ _rotr64(x, 41);
}

inline uint32_t sig0(uint32_t x)
{
	return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3);
}

inline uint64_t sig0(uint64_t x)
{
	return _rotr64(x, 1) ^ _rotr64(x, 8) ^ (x >> 7);
}

inline uint32_t sig1(uint32_t x)
{
	return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10);
}

inline uint64_t sig1(uint64_t x)
{
	return _rotr64(x, 19) ^ _rotr64(x, 61) ^ (x >> 6);
}


//SHA1 functions f,g, etc. distingished by parameter t
inline uint32_t SHA1_f(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
{
	if (t < 20)
		return ch(x, y, z) + 0x5a827999;
	else if (t < 40)
		return parity(x, y, z) + 0x6ed9eba1;
	else if (t < 60)
		return maj(x, y, z) + 0x8f1bbcdc;
	else
		return parity(x, y, z) + 0xca62c1d6;
}
//end of auxilliary functions

SHA1_class::SHA1_class()
{
	reset();
}

void SHA1_class::reset()
{
	//set initial hash values, from RFC
	h[0] = 0x67452301;
	h[1] = 0xefcdab89;
	h[2] = 0x98badcfe;
	h[3] = 0x10325476;
	h[4] = 0xc3d2e1f0;
	//reset length and current block counters
	ctr = 0;
	_length = 0;
}

//why the fuck does this function even exist?
//add data in the buffer to the hash
void SHA1_class::add_buffer()
{
	compress(h, buffer);
	ctr = 0;
}

//add data (as a vector of bytes) to the hash
void SHA1_class::addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end)
{
	size_t dlen = end - begin;
	//if the current block is partially filled...
	if (ctr > 0)
	{
		//how much data are we adding to the current block?
		//either all of it, or enough to fill up the block.
		size_t sz = min(dlen, 64 - ctr);
		//copy data into block
		memcpy(buffer + ctr, &*begin, sz);
		//if the block is now full...
		if (sz == 64 - ctr)
			add_buffer(); //...add the full block to the hash.
		else
			ctr += sz; //otherwise, update size of current block
		dlen -= sz; //decrease count of data remaining by amount we just added
	}
	//while we have a whole block remaining (we won't if current block is still partial)
	while (end - begin >= 64)
	{
		compress(h, (uint8_t*)&*begin); //add the next 64 bytes of data to the hash
		begin+=64; //decrease data remaining counter
	}
	//if there's a partial block left...
	if (dlen != 0)
	{
		memcpy(buffer, &*begin, end-begin);//...copy partial block into current block
		ctr = end-begin; //set partial block length counter
	}
	_length += dlen * 8; //increase message length counter
}

std::istream& SHA1_class::addData(std::istream& inbuf) {
	do {
		inbuf.read((char*)&buffer[ctr], get_block_length() - ctr);
		if (inbuf) {
			compress(h, buffer);
			ctr = 0;
		}
		else {
			ctr += inbuf.gcount();
		}
	} while (inbuf);
	return inbuf;
}

//get hash value for data added so far
charBuf SHA1_class::finalise() const
{
	charBuf out(20);
	finalise(out.begin());
	return  out;
}

void SHA1_class::finalise(std::vector<char>::iterator it) const {
	uint8_t tmp[64];
	uint32_t g[5];
	size_t tctr = ctr; //temp copy of blocklen counter
					   //copy current partial block and hash values into temp vars
	memcpy(tmp, buffer, ctr);
	memcpy(g, h, 5 * sizeof(g[0]));
	//put a single on bit after the message
	//(partial block always has at least one byte empty)
	tmp[tctr] = 0x80;
	++tctr;
	//if we don't have space in the current block to append the length...
	if (tctr > 56)
	{
		//...pad out the current block with zeroes, and add it to the hash
		memset(tmp + tctr, 0, 64 - tctr);
		compress(g, tmp);
		tctr = 0;
	}
	//pad the current block (which may be empty) until
	//we have just enough space left for the length
	memset(tmp + tctr, 0, 56 - tctr);
	//append the length of the message in bits, completing the block
	writeword64(_length, tmp + 56);
	//and then add the very final block to the hash
	compress(g, tmp);
	//and write the final hash values to a vector of bytes
	for (int i = 0; i < 5; ++i)
		writeword(g[i], (uint8_t*)&*it);
}

void SHA1_class::compress(uint32_t IV[5], uint8_t const * const data_in)
{
	uint32_t w[80]; //message schedule
	uint32_t g[5]; //temp vars, a...h
	uint32_t T; //temp variable
	//fill first 16 words of schedule with message chunk
	for (int t = 0; t < 16; ++t)
		w[t] = getword(data_in + (4 * t));
	//expand rest of schedule
	for (int t = 16; t < 80; ++t)
		w[t] = _rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
	//copy IV into working variables
	memcpy(g, IV, 20);
	//main compression loop
	for (int t = 0; t < 80; ++t)
	{
		T = _rotl(g[0], 5) + SHA1_f(g[1], g[2], g[3],t) + g[4] + w[t];
		for (int i = 4; i >0; --i)
			g[i] = g[i - 1];
		g[2] = _rotl(g[2], 30);
		g[0] = T;
	}
	//add result to IV
	for (int j = 0; j < 5; ++j)
		IV[j] += g[j];
}

size_t SHA1_class::get_hash_length() const
{
	return 20;
}

size_t SHA1_class::get_block_length() const
{
	return 64;
}

std::shared_ptr<HashFunction> SHA1_class::clone() const
{
	return std::shared_ptr<HashFunction>(new SHA1_class(*this));
}

SHA256_class::SHA256_class()
{
	reset();
}

void SHA256_class::reset()
{
	h[0] = 0x6a09e667;
	h[1] = 0xbb67ae85;
	h[2] = 0x3c6ef372;
	h[3] = 0xa54ff53a;
	h[4] = 0x510e527f;
	h[5] = 0x9b05688c;
	h[6] = 0x1f83d9ab;
	h[7] = 0x5be0cd19;
	ctr = 0;
	_length = 0;
}

void SHA256_class::compress(uint32_t IV[8], uint8_t const * const data_in)
{
	uint32_t w[64]; //message schedule
	uint32_t g[8]; //temp vars, a...h
	//fill first 16 words of schedule with message chunk
	for (int j = 0; j < 16; ++j)
		w[j] = getword(data_in + (4 * j));
	//expand rest of schedule
	for (int j = 16; j < 64; ++j)
		w[j] = sig1(w[j - 2]) + w[j - 7] + sig0(w[j - 15]) + w[j - 16];
	//copy IV into working variables
	memcpy(g, IV, 32);
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
	//add result to IV
	for (int j = 0; j < 8; ++j)
		IV[j] += g[j];
}

void SHA256_class::add_buffer()
{
	compress(h, buffer);
	ctr = 0;
}

std::istream& SHA256_class::addData(std::istream& inbuf) {
	do {
		inbuf.read((char*)&buffer[ctr], get_block_length() - ctr);
		if (inbuf) {
			compress(h, buffer);
			ctr = 0;
		} else {
			ctr += inbuf.gcount();
		}
	} while (inbuf);
	return inbuf;
}

void SHA256_class::addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end) {
	size_t dlen = end-begin;
	if (ctr > 0)
	{
		size_t sz = min(dlen, 64 - ctr);
		memcpy(&buffer[ctr], &*begin, sz);
		if (sz == 64 - ctr)
			add_buffer();
		else
			ctr += sz;
		begin += sz;
	}
	while (end-begin >= 64)
	{
		compress(h, (uint8_t*)&*begin);
		begin += 64;
	}
	if (begin != end)
	{
		memcpy(buffer, &*begin, end-begin);
		ctr = end-begin;
	}
	_length += dlen * 8;
}


void SHA256_class::finalise(std::vector<char>::iterator it) const {
	uint8_t tmp[64];
	uint32_t g[8];
	size_t tctr = ctr;
	//for (size_t i = 0; i < tctr; ++i)
	//	tmp[i] = buffer[i];
	memcpy(tmp, buffer, tctr);
	//for (size_t i = 0; i < 8; ++i)
	//	g[i] = h[i];
	memcpy(g, h, 32);
	tmp[tctr] = 0x80;
	++tctr;
	if (tctr > 56)
	{
		//for (size_t i = tctr; i < 64; ++i)
		//	tmp[i] = 0;
		memset(tmp + tctr, 0, 64 - tctr);
		compress(g, tmp);
		tctr = 0;
	}
	//for (size_t i = tctr; i < 56; ++i)
	//	tmp[i] = 0;
	memset(tmp + tctr, 0, 56 - tctr);
	writeword64(_length, &tmp[56]);
	compress(g, tmp);
	for (int i = 0; i < 8; ++i)
		writeword(g[i], (uint8_t*)&*it);
}

std::vector<char> SHA256_class::finalise() const
{
	charBuf out(32);
	finalise(out.begin());
	return out;
}

size_t SHA256_class::get_hash_length() const
{
	return 32;
}

size_t SHA256_class::get_block_length() const
{
	return 64;
}

std::shared_ptr<HashFunction> SHA256_class::clone() const
{
	return std::shared_ptr<HashFunction>(new SHA256_class(*this));
}

SHA224_class::SHA224_class()
{
	reset();
}

void SHA224_class::reset()
{
	//must call superclass reset to reset private members
	SHA256_class::reset();
	h[0] = 0xc1059ed8;
	h[1] = 0x367cd507;
	h[2] = 0x3070dd17;
	h[3] = 0xf70e5939;
	h[4] = 0xffc00b31;
	h[5] = 0x68581511;
	h[6] = 0x64f98fa7;
	h[7] = 0xbefa4fa4;
}

charBuf SHA224_class::finalise() const
{
	charBuf ret = SHA256_class::finalise();
	ret.resize(28);
	return ret;
}

void SHA224_class::finalise(std::vector<char>::iterator it) const {
	charBuf buffer = finalise();
	memcpy(&*it, &buffer[0], get_hash_length());
}

size_t SHA224_class::get_hash_length() const
{
	return 28;
}

std::shared_ptr<HashFunction> SHA224_class::clone() const
{
	return std::shared_ptr<HashFunction>(new SHA224_class(*this));
}

ctr128& operator+=(ctr128& lhs, const ctr128& rhs)
{
	uint64_t tmp = lhs.low + rhs.low;
	if (tmp < lhs.low)
		++lhs.high;
	lhs.low = tmp;
	lhs.high += rhs.high;
	return lhs;
}

ctr128& operator+=(ctr128& lhs, const uint64_t& rhs)
{
	uint64_t tmp = lhs.low + rhs;
	if (tmp < lhs.low)
		++lhs.high;
	lhs.low = tmp;
	return lhs;
}

ctr128 operator+(ctr128 lhs, const ctr128& rhs)
{
	lhs += rhs;
	return lhs;
}

ctr128 operator+(ctr128 lhs, const uint64_t& rhs)
{
	lhs += rhs;
	return lhs;
}

ctr128& operator++(ctr128& lhs)
{
	++lhs.low;
	if (!lhs.low)
		++lhs.high;
	return lhs;
}

ctr128 operator++(ctr128& lhs, int)
{
	ctr128 tmp = lhs;
	++lhs;
	return tmp;
}

SHA512_class::SHA512_class()
{
	reset();
}

void SHA512_class::reset()
{
	h[0] = 0x6a09e667f3bcc908LL;
	h[1] = 0xbb67ae8584caa73bLL;
	h[2] = 0x3c6ef372fe94f82bLL;
	h[3] = 0xa54ff53a5f1d36f1LL;
	h[4] = 0x510e527fade682d1LL;
	h[5] = 0x9b05688c2b3e6c1fLL;
	h[6] = 0x1f83d9abfb41bd6bLL;
	h[7] = 0x5be0cd19137e2179LL;
	_length = { 0, 0 };
	ctr = 0;
}

std::istream& SHA512_class::addData(std::istream& inbuf) {
	do {
		inbuf.read((char*)&buffer[ctr], get_block_length() - ctr);
		if (inbuf) {
			compress(h, buffer);
			ctr = 0;
		}
		else {
			ctr += inbuf.gcount();
		}
	} while (inbuf);
	return inbuf;
}

void SHA512_class::addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end)
{
	size_t dlen = end-begin;
	if (ctr > 0)
	{
		size_t sz = min(dlen, 128 - ctr);
		memcpy(&buffer[ctr], &*begin, sz);
		if (sz == 128 - ctr)
			add_buffer();
		else
			ctr += sz;
		begin += sz;
	}
	while (end-begin >= 128)
	{
		compress(h, (uint8_t*)&*begin);
		begin += 128;
	}
	if (begin != end)
	{
		memcpy(buffer, &*begin, end-begin);
		ctr = end-begin;
	}
	_length += dlen * 8;
}

void SHA512_class::finalise(std::vector<char>::iterator it) const {
	uint8_t tmp[128];
	uint64_t g[8];
	size_t tctr = ctr;
	for (size_t i = 0; i < tctr; ++i)
		tmp[i] = buffer[i];
	for (size_t i = 0; i < 8; ++i)
		g[i] = h[i];
	tmp[tctr] = 0x80;
	++tctr;
	if (tctr > 112)
	{
		for (size_t i = tctr; i < 128; ++i)
			tmp[i] = 0;
		compress(g, tmp);
		tctr = 0;
	}
	for (size_t i = tctr; i < 112; ++i)
		tmp[i] = 0;

	writeword64(_length.high, &tmp[112]);
	writeword64(_length.low, &tmp[120]);
	compress(g, tmp);
	for (int i = 0; i < 8; ++i)
		writeword64(g[i], (uint8_t*)&*it);
}

std::vector<char> SHA512_class::finalise() const
{
	charBuf out(64);
	finalise(out.begin());
	return out;
}

size_t SHA512_class::get_hash_length() const
{
	return 64;
}

size_t SHA512_class::get_block_length() const
{
	return 128;
}

void SHA512_class::compress(uint64_t IV[8], uint8_t const * const data_in)
{
	uint64_t w[80]; //message schedule
	uint64_t g[8]; //temp vars, a...h
	uint64_t tmp1, tmp2;
	//fill first 16 words of schedule with message chunk
	for (int j = 0; j < 16; ++j)
		w[j] = getword64(data_in + (8 * j));
	//expand rest of schedule
	for (int j = 16; j < 80; ++j)
		w[j] = sig1(w[j - 2]) + w[j - 7] + sig0(w[j - 15]) + w[j - 16];
	//copy IV into working variables
	for (int j = 0; j < 8; ++j)
		g[j] = IV[j];
	//main compression loop
	for (int t = 0; t < 80; ++t)
	{
		tmp1 = g[7] + capsig1(g[4]) + ch(g[4], g[5], g[6]) + K64[t] + w[t];
		tmp2 = capsig0(g[0]) + maj(g[0], g[1], g[2]);
		for (int i = 7; i > 0; --i)
			g[i] = g[i - 1];
		g[4] += tmp1;
		g[0] = tmp1 + tmp2;
	}
	//add result to IV
	for (int j = 0; j < 8; ++j)
		IV[j] += g[j];
}

void SHA512_class::add_buffer()
{
	compress(h, buffer);
	ctr = 0;
}

std::shared_ptr<HashFunction> SHA512_class::clone() const
{
	return std::shared_ptr<HashFunction>(new SHA512_class(*this));
}

SHA384_class::SHA384_class()
{
	reset();
}

void SHA384_class::reset()
{
	//must call superclass reset to reset its private members
	SHA512_class::reset();
	h[0] = 0xcbbb9d5dc1059ed8LL;
	h[1] = 0x629a292a367cd507LL;
	h[2] = 0x9159015a3070dd17LL;
	h[3] = 0x152fecd8f70e5939LL;
	h[4] = 0x67332667ffc00b31LL;
	h[5] = 0x8eb44a8768581511LL;
	h[6] = 0xdb0c2e0d64f98fa7LL;
	h[7] = 0x47b5481dbefa4fa4LL;
}

charBuf SHA384_class::finalise() const
{
	charBuf ret = SHA512_class::finalise();
	ret.resize(48);
	return ret;
}

void SHA384_class::finalise(std::vector<char>::iterator it) const {
	charBuf buffer = finalise();
	memcpy(&*it, &buffer[0], get_hash_length());
}

size_t SHA384_class::get_hash_length() const
{
	return 48;
}

std::shared_ptr<HashFunction> SHA384_class::clone() const
{
	return std::shared_ptr<HashFunction>(new SHA384_class(*this));
}

size_t powten(size_t n)
{
	if (n <= 0)
		return 1;
	return 10 * powten(n - 1);
}

uint32_t HOTP(const charBuf& K, uint64_t ctr, size_t digits)
{
	//convert integer counter to bitstring
	charBuf C(8);
	for (int i = 7; i >= 0; --i)
	{
		C[i] = ctr & 0xFF;
		ctr >>= 8;
	}
	//calculate HMAC-SHA-1 value
	charBuf hsh = HMAC<SHA1_class>(K, C);

	//Dynamic truncation
	uint8_t offset = hsh[19] & 0xF;
	uint32_t P = 0;
	for (int i = 0; i < 4; ++i)
		P += uint32_t(hsh[offset + i]) << (8 * (3 - i));
	P &= 0x7FFFFFFF;
	//reduce to given number of decimal digits
	P %= powten(digits);
	return P;
}

totp_return TOTP(const charBuf& K, size_t digits, size_t lookahead, std::time_t X, std::time_t epoch)
{
	//get number of timesteps since the epoch
	uint64_t T = (time(0) - epoch) / X;
	T += lookahead; //apply offset to get next or previous codes
	return{ HOTP(K, T, digits), T }; //use the timestep count as counter for HOTP
}