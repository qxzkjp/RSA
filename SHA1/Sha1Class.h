#pragma once
#include "Buffer.h"
#include "../RSA/interfaces.h"

class PointedBuffer : public Buffer
{
public:
	PointedBuffer(size_t n);
	PointedBuffer(const PointedBuffer& pb);
	PointedBuffer(PointedBuffer&& pb);
	PointedBuffer& operator=(const PointedBuffer& pb);
	PointedBuffer& operator=(PointedBuffer&& pb);
	void addData(const BYTE* ptr, size_t n);
	void addData(const BYTE* ptr);
	void addData(const Buffer buf);
	std::istream& addData(std::istream& is);
	void reset();
	size_t getPos();
	size_t remaining();
private:
	size_t _pos;
};

class Sha1Class : virtual public HashFunction {
public:
	Sha1Class();
	void reset();
	void addData(const std::vector<char>& v);
	void addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end);
	std::istream& addData(std::istream& is);
	std::vector<char> finalise();
	void finalise(std::vector<char>::iterator it);
	size_t length();
	hashPtr clone();
private:
	void addChunk();
	void addChunkToState(const BYTE* buf, uint32_t h[5]);
	uint32_t _h[5];
	uint64_t _size;
	PointedBuffer _buf;
};

charBuf doSha1(std::istream& is);

void reverseMemcpy(void* dst, void* src, size_t cnt);

//uint32_t ROTL(uint32_t a, size_t n);