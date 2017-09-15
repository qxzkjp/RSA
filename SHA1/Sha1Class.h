#pragma once
#include "../RSA/Buffer.h"
#include "../RSA/interfaces.h"
#include "PointedBuffer.h"

class Sha1Class : public HashFunction {
public:
	Sha1Class();
	void reset();
	void addData(const std::vector<char>& v);
	std::istream& addData(std::istream& is);
	std::vector<char> finalise();
private:
	void addChunk();
	void addChunkToState(const BYTE* buf, uint32_t h[5]);
	uint32_t _h[5];
	uint64_t _size;
	PointedBuffer _buf;
};

//void reverseMemcpy(void* dst, void* src, size_t cnt);

//uint32_t ROTL(uint32_t a, size_t n);