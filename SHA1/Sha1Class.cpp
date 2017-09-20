#include "stdafx.h"
#include "Sha1Class.h"
#include "../RSA/memoryhelper.h"

uint32_t ROTL(uint32_t a, size_t n) {
	return (a << n) | (a >> (32 - n));
}

Sha1Class::Sha1Class() : _buf(PointedBuffer(64)), _size(0)
{
	_h[0] = 0x67452301;
	_h[1] = 0xEFCDAB89;
	_h[2] = 0x98BADCFE;
	_h[3] = 0x10325476;
	_h[4] = 0xC3D2E1F0;
}
void Sha1Class::reset() {
	_h[0] = 0x67452301;
	_h[1] = 0xEFCDAB89;
	_h[2] = 0x98BADCFE;
	_h[3] = 0x10325476;
	_h[4] = 0xC3D2E1F0;
	_buf.reset();
	_size = 0;
}

void Sha1Class::addData(const std::vector<char>& v) {
	size_t inpos = 0;
	_size += v.size();
	//if we have enough extra data to finish the current chunk, copy in enough data to fill the chunk and add it to the state
	if (v.size() >= _buf.remaining()) {
		inpos += _buf.remaining();
		_buf.addData((BYTE*)&v[0]);
		addChunk();
		//then, add  whole chunks from the input buffer until we have less than a whole chunk left
		while (v.size() - inpos >= _buf.size()) {
			addChunkToState((BYTE*)&v[inpos], _h);
			inpos += _buf.size();
		}
		//then we copy the remainder (if any) into the beginning of our current chunk, and leave it alone
		if(v.size() > inpos)
			_buf.addData((BYTE*)&v[inpos], v.size() - inpos);
	}
	//otherwise, copy all the data into the chunk and leave it alone
	else if (v.size() > 0) {
		_buf.addData((BYTE*)&v[0], v.size());
	}
}

void Sha1Class::addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end)
{
	size_t inpos = 0;
	size_t inSize = end - begin;
	_size += inSize;
	//if we have enough extra data to finish the current chunk, copy in enough data to fill the chunk and add it to the state
	if (inSize >= _buf.remaining()) {
		inpos += _buf.remaining();
		_buf.addData((BYTE*)&begin[0]);
		addChunk();
		//then, add  whole chunks from the input buffer until we have less than a whole chunk left
		while (inSize - inpos >= _buf.size()) {
			addChunkToState((BYTE*)&begin[inpos], _h);
			inpos += _buf.size();
		}
		//then we copy the remainder (if any) into the beginning of our current chunk, and leave it alone
		if (inSize > inpos)
			_buf.addData((BYTE*)&begin[inpos], inSize - inpos);
	}
	//otherwise, copy all the data into the chunk and leave it alone
	else if (inSize > 0) {
		_buf.addData((BYTE*)&begin[0], inSize);
	}
}

std::istream& Sha1Class::addData(std::istream& is) {
	if (_buf.addData(is))
		addChunk();
	_size += is.gcount();
	while (_buf.addData(is)) {
		_size += _buf.size();
		addChunk();
	}
	_size += is.gcount();
	return is;
}
std::vector<char> Sha1Class::finalise() {
	std::vector<char> ret(length());
	finalise(ret.begin());
	return ret;
}

void Sha1Class::finalise(std::vector<char>::iterator it){
	//if (v.size() < length())
	//	v.resize(length()); //if not enough space in the buffer, resize it
	//set up temp state for final block
	Buffer tmp = _buf;
	size_t tpos = _buf.getPos();
	uint64_t tsize = _size * 8;
	uint32_t tmph[5];
	for (int i = 0; i < 5; ++i)
		tmph[i] = _h[i];
	//append 0x80 to message, this is not counted in length
	tmp[tpos++] = 0x80;
	//the rest of the block is zeroed
	memset(&tmp[tpos], 0, tmp.size() - tpos);
	//if we don't have enough space for the size in this chunk, add the chunk as-is and then make a blank chunk
	if (tpos > 56) {
		addChunkToState(&tmp[0], tmph);
		memset(&tmp[0], 0, tmp.size());
	}
	//copy size (in bits) into final bytes of the final chunk (big-endian)
	reverseMemcpy(&tmp[56], &tsize, sizeof(uint64_t));
	//add the final chunk to the temp state
	addChunkToState(&tmp[0], tmph);
	//copy h-values as big-endian to the output buffer. this is the final hash result.
	for (int i = 0; i < 5; ++i) {
		char* ptr = (char*)(tmph + i);
		for (int j = 3; j >= 0; --j) {
			*it = *(ptr + j);
			++it;
		}
	}
}

void Sha1Class::addChunk() {
	addChunkToState(&_buf[0], _h);
	_buf.reset();
}
void Sha1Class::addChunkToState(const BYTE* buf, uint32_t h[5]) {
	uint32_t w[80];
	uint32_t* ptr = (uint32_t*)buf;
	for (int i = 0; i < 16; ++i) {
		reverseMemcpy(w + i, ptr, sizeof(uint32_t));
		++ptr;
	}
	for (int i = 16; i < 80; ++i) {
		w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
		w[i] = ROTL(w[i], 1); //ROTL 1
	}
	uint32_t a = h[0];
	uint32_t b = h[1];
	uint32_t c = h[2];
	uint32_t d = h[3];
	uint32_t e = h[4];
	uint32_t f, k, temp;
	for (int t = 0; t < 80; ++t) {
		if (t < 20) {
			f = (b & c) | ((~b) & d);
			k = 0x5A827999;
		}
		else if (t < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		}
		else if (t < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		}
		else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}
		temp = ROTL(a, 5) + f + e + k + w[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = temp;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

size_t Sha1Class::length() {
	return 20;
}

hashPtr Sha1Class::clone() {
	return std::make_shared<Sha1Class>(*this);
}
