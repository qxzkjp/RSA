#pragma once
#include "../RSA/Buffer.h"

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
