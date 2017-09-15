#pragma once
#include "../RSA/Buffer.h"

class PointedBuffer : public Buffer
{
public:
	PointedBuffer(size_t n);
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
