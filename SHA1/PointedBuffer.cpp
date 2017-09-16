#include "stdafx.h"
#include "PointedBuffer.h"

PointedBuffer::PointedBuffer(size_t n) : Buffer(n), _pos(0) {}

PointedBuffer::PointedBuffer(const PointedBuffer& pb) : Buffer(pb), _pos(pb._pos) {}

PointedBuffer::PointedBuffer(PointedBuffer&& pb) : Buffer(pb), _pos(pb._pos) {}

PointedBuffer& PointedBuffer::operator=(const PointedBuffer& pb) {
	Buffer::operator=(pb);
	_pos = pb._pos;
	return *this;
}

PointedBuffer& PointedBuffer::operator=(PointedBuffer&& pb) {
	Buffer::operator=(pb);
	_pos = pb._pos;
	return *this;
}

void PointedBuffer::addData(const BYTE* ptr, size_t n) {
	if (_pos + n > _sz)
		throw 5; //die on memeory overflow
	memcpy(&_data[_pos], ptr, n);
	_pos += n;
}

void PointedBuffer::addData(const BYTE* ptr) {
	addData(ptr, _sz - _pos);
}

void PointedBuffer::addData(const Buffer buf) {
	addData(buf.raw(), buf.size());
}

std::istream& PointedBuffer::addData(std::istream& is) {
	is.read((char*)&_data[_pos], remaining());
	if (is)
		_pos = _sz;
	else
		_pos += is.gcount();
	return is;
}

void PointedBuffer::reset() {
	_pos = 0;
}

size_t PointedBuffer::getPos() {
	return _pos;
}

size_t PointedBuffer::remaining() {
	return _sz - _pos;
}